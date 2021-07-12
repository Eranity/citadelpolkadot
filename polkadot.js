require('../utils/array_chunk');
const BigNumber = require('bignumber.js');
const { ApiPromise } = require('@polkadot/api');
const { WsProvider } = require('@polkadot/rpc-provider');
const { hexToString, isHex } = require('@polkadot/util');
const Transactions = require('../models/Transactions2');
const { decodeAddress, encodeAddress } = require('@polkadot/util-crypto');

const config = require('../config');

const provider = new WsProvider(config.polkadot.websocket);
//const provider = new HttpProvider(config.polkadot.host);
const api = new ApiPromise({ provider });

const DOT_DECIMAL_PLACES = 10000000000;
const zabbixItemsHost = 'CitadelConnectorPolkadot';
const APPROX_ERA_DURATION = 1000 * 3600 * 24; // approximately era duration: 24 hours

const methods = {
	isSystemAddress: null,
	validateAddress: null,
	getLastBlock: null,
	getOneBlock: null,
	filterOperations: null,
	prepareTransfer: null,
	prepareDelegations: null,
	prepareDelegation: null,
	prepareUndelegation: null,
	getDelegationBalanceInfo: null,
	prepareStakeAndDelegate: null,
	prepareStake: null,
	prepareUnstake: null,
	prepareClaimUnstaked: null,
	prepareClaimReward: null,
	prepareListOfNodes: null,
	prepareListOfValidators: null,
	signAndSendTransaction: null,
	sendTransaction: null,
	decodeTransactions: null,
	getOneTransaction: null,
	multiplier: DOT_DECIMAL_PLACES,
	zabbixItemsHost
};

module.exports = methods;

async function getHashOfBlock (number) {
	try {
		await api.isReadyOrError;
		return await api.rpc.chain.getBlockHash(number);
	} catch (e) {
		console.error('Polkadot: can\'t get hash of block ' + number, e);
		throw e;
	}
}

async function getBlockTxs (opt) {
	const hash = await getHashOfBlock(opt.blockNumber);
	opt.blockHash = hash;

	try {
		return (await api.rpc.chain.getBlock(hash)).block;
	} catch (e) {
		console.error('Polkadot: can\'t load block ' + opt.blockNumber, e);
		throw e;
	}
}

methods.getLastBlock = async function () {
	try {
		await api.isReadyOrError;
		return parseInt((await api.rpc.chain.getBlock()).block.header.number.toHuman().replace(/,/g, ''));
	} catch (e) {
		console.error('Polkadot: failed getLastBlock', e);
		throw e;
	}
};

methods.isSystemAddress = function () {
	return false;
};

methods.validateAddress = address => /([a-zA-Z0-9]+)$/.test(address);

methods.getOneBlock = async (opt) => {
	let { blockNumber, throws } = opt;
	let transactions = [];
	let nodeResponseTime = new Date().getTime();
	let txs = await getBlockTxs(opt);
	try {
		nodeResponseTime = new Date().getTime() - nodeResponseTime;
		let humanTxs = txs.toHuman();
		var block_info = {
			blockNumber: humanTxs.header.number.replace(/,/g, ''),
			originalTxsCount: humanTxs.extrinsics.length - 1,
			blockDate: new Date(parseInt(humanTxs.extrinsics[0].method.args[0].replace(/,/g, ''))).toISOString(),
			prepareTime: nodeResponseTime,
		};
		if (txs.extrinsics.length === 1) {
			console.log(`Block ${blockNumber} doesn't include transactions`);
			return { transactions, block_info };
		}
		await methods.filterOperations(txs, opt, transactions);

	} catch (err) {
		if (throws) {
			throw new Error(err.response ? err.response.status + ' ' + err.response.statusText : err);
		} else {
			console.error(err.response ? err.response.status + ' ' + err.response.statusText : err);
		}
	}
	return { transactions, block_info };
};

methods.getOneTransaction = async function (hash) {
	const tx = await Transactions.findOne({
		where: {
			hash,
			currency: 'polkadot'
		}
	});
	return tx || null;
};

methods.decodeTransactions = async (signedTransaction) =>{
	let transactions = [];
	await methods.filterOperations(
		{ extrinsics: [signedTransaction] }, 
		{ isMempool: true }, 
		transactions
	);	
	return transactions;
};


methods.filterOperations = async (txs, opt, transactions = []) => {
	const { blockNumber, blockHash, isMempool } = opt;
	await api.isReadyOrError;

	let transaction_pattern = {
		originalOpType: '',
		hash: '',
		date: '',
		from: '',
		to: '',
		type: 'transfer',
		comment: '',
		isCanceled: false,
		currency: 'polkadot',
		deltaFrom: 0,
		deltaTo: 0,
		blockNumber
	};

	if (txs.extrinsics[0].toHuman().method.method === 'set' && txs.extrinsics[0].toHuman().method.section === 'timestamp') {
		transaction_pattern.date = new Date(parseInt(txs.extrinsics[0].toHuman().method.args[0].replace(/,/g, ''))).toISOString();
	}

	const allRecords = await api.query.system.events.at(blockHash);

	let signer, notCanceled = true, index = -1;
	for (let tx of txs.extrinsics) {
		index++;
		const hash = tx.hash.toHex();
		if (opt.hash && hash !== opt.hash) continue;
		signer = prepareAddress(tx.signer.toHuman());
		let transaction = { ...transaction_pattern };
		const records = allRecords.filter(({ phase }) => phase.isApplyExtrinsic && phase.asApplyExtrinsic.eq(index));
		const events = records.map(({ event }) => event.method);

		transaction.hash = hash;
		tx = tx.toHuman();
		const { method } = tx;

		records.forEach(({ phase, event }) => {
			const eventTransaction = { ...transaction_pattern };
			if (phase.isApplyExtrinsic) {
				if (api.events.balances.Deposit.is(event)) {
					const [ to, value ] = event.data;
					eventTransaction.hash = hash;
					eventTransaction.originalOpType = 'deposit';
					eventTransaction.type = 'fees';
					eventTransaction.deltaFrom = -(value / DOT_DECIMAL_PLACES);
					eventTransaction.deltaTo = value / DOT_DECIMAL_PLACES;
					eventTransaction.from = signer;
					eventTransaction.to = to.toString();
					transactions.push({ ...eventTransaction });
				} else if (api.events.staking.Reward.is(event) && notCanceled) {
					const [ to, value ] = event.data;
					eventTransaction.hash = hash;
					eventTransaction.originalOpType = 'reward';
					eventTransaction.type = 'reward';
					eventTransaction.deltaTo = value / DOT_DECIMAL_PLACES;
					eventTransaction.to = to.toString();
					transactions.push({ ...eventTransaction });
				} else if (api.events.staking.Unbonded.is(event) && notCanceled) {
					// eslint-disable-next-line no-unused-vars
					const [ to, value ] = event.data;
					eventTransaction.hash = hash;
					eventTransaction.originalOpType = 'unbonded';
					eventTransaction.type = 'unstake';
					eventTransaction.comment = value / DOT_DECIMAL_PLACES;
					eventTransaction.to = signer;
					transactions.push({ ...eventTransaction });
				} else if (api.events.staking.Withdrawn.is(event) && notCanceled) {
					// eslint-disable-next-line no-unused-vars
					const [ from, value ] = event.data;
					eventTransaction.hash = hash;
					eventTransaction.originalOpType = 'withdrawn';
					eventTransaction.type = 'unstake';
					eventTransaction.deltaTo = value / DOT_DECIMAL_PLACES;
					eventTransaction.to = signer;
					transactions.push({ ...eventTransaction });
				} else if (api.events.treasury.Deposit.is(event)) {
					const [value] = event.data;
					eventTransaction.hash = hash;
					eventTransaction.originalOpType = 'treasury';
					eventTransaction.type = 'fees';
					eventTransaction.deltaFrom = -(value / DOT_DECIMAL_PLACES);
					eventTransaction.deltaTo = value / DOT_DECIMAL_PLACES;
					eventTransaction.from = signer;
					transactions.push({ ...eventTransaction });
				} else if (api.events.balances.Transfer.is(event) && notCanceled) {
					const [ from, to, value ] = event.data;
					eventTransaction.hash = hash;
					eventTransaction.originalOpType = 'transfer';
					eventTransaction.type = 'transfer';
					eventTransaction.deltaFrom = -(value / DOT_DECIMAL_PLACES);
					eventTransaction.deltaTo = value / DOT_DECIMAL_PLACES;
					eventTransaction.from = from.toString();
					eventTransaction.to = to.toString();
					transactions.push({ ...eventTransaction });
				}
			}
		});

		if (events.includes('ExtrinsicFailed')) {
			notCanceled = false;
			transaction.isCanceled = true;
			if ([ 'transfer', 'transferKeepAlive' ].includes(method.method)) {
				prepateTransaction(transactions, transaction, method, tx);
			}
		}

		if (method.method === 'set' && method.section === 'timestamp') {
			continue;
		}
		if (method.method === 'batch' || method.method === 'batchAll') {
			transaction.originalOpType = method.method;
			for (let item of method.args) {
				for (let ex of item) {
					transaction.deltaFrom = 0;
					transaction.deltaTo = 0;
					if ([ 'bond', 'bondExtra', 'nominate', 'chill', 'rebond', 'setPayee', 'validate', 'setIdentity', 'payout', 'payoutStakers' ].includes(ex.method))
						prepateTransaction(transactions, transaction, ex, tx);
					else if (isMempool) {
						prepateTransaction(transactions, transaction, ex, tx);
					}
				}
			}
			continue;
		} else if ([ 'bond', 'bondExtra', 'nominate', 'chill', 'rebond', 'setPayee', 'validate', 'setIdentity', 'payout', 'payoutStakers' ].includes(method.method)) {
			prepateTransaction(transactions, transaction, method, tx);
		} else if (isMempool) {
			prepateTransaction(transactions, transaction, method, tx);
		} else {
			continue;
		}
	}

	return transactions;
};

const prepateTransaction = function (transactions,transaction, method, tx) {
	if (method.method === 'nominate') {
		transaction.type = 'stake';
		transaction.originalOpType = 'nominate';
		transaction.from = prepareAddress(tx.signer);
		for (let item of method.args) {
			for (let validator of item) {
				transaction.to = prepareAddress(validator);
				transactions.push({ ...transaction });
			}
		}
		return;
	} else if (method.method === 'transfer' || method.method === 'transferKeepAlive' || method.method === 'forceTransfer') {
		transaction.originalOpType = method.method;
		transaction.deltaFrom = -prepareValue(method.args[1]);
		transaction.deltaTo = prepareValue(method.args[1]);
		transaction.from = prepareAddress(tx.signer);
		transaction.to = prepareAddress(method.args[0]);
	} else if (method.method === 'bond') {
		transaction.type = 'stake';
		transaction.originalOpType = 'bond';
		transaction.deltaFrom = -prepareValue(method.args[1]);
		transaction.from = prepareAddress(tx.signer);
	} else if (method.method === 'bondExtra') {
		transaction.type = 'stake';
		transaction.originalOpType = 'bondExtra';
		transaction.deltaFrom = -prepareValue(method.args[0]);
		transaction.from = prepareAddress(tx.signer);
	} else if (method.method === 'chill') {
		transaction.type = 'unstake';
		transaction.originalOpType = method.method;
		transaction.from = prepareAddress(tx.signer);
	} else if (method.method === 'rebond') {
		transaction.type = 'stake';
		transaction.originalOpType = method.method;
		transaction.deltaFrom = -prepareValue(method.args[0]);
		transaction.deltaTo = prepareValue(method.args[0]);
		transaction.from = prepareAddress(tx.signer);
	} else if ([ 'setPayee', 'validate', 'setIdentity' ].includes(method.method)) {
		transaction.type = 'unsupported';
		transaction.originalOpType = method.method;
		transaction.from = prepareAddress(tx.signer);
	} else if (method.method === 'payoutStakers') {
		transaction.type = 'unsupported';
		transaction.originalOpType = method.method;
		transaction.from = prepareAddress(tx.signer);
		transaction.to = prepareAddress(method.args[0]);
	}
	transactions.push({ ...transaction });
};

const prepareAddress = function (address) {
	if (typeof address === 'object') {
		if (address.Id) return address.Id;
		if (address.Address20) return address.Address20;
		if (address.Address32) return encodeAddress(decodeAddress(address.Address32), 0);
	}
	return address;
};

const prepareValue = function (value) {
	if (value.includes('kDOT')) return parseFloat(value) * 1000;
	if (value.includes('mDOT')) return parseFloat(value) / 1000;
	return parseFloat(value);
};

const prepareSignerPayload = async (from, tx, tip = 0) => {
	const { nonce } = await api.query.system.account(from);
	const transaction = api.tx(tx);
	const signer = api.createType('SignerPayload', {
		method: transaction,
		nonce,
		genesisHash: api.genesisHash,
		blockHash: api.genesisHash,
		runtimeVersion: api.runtimeVersion,
		version: api.extrinsicVersion,
		tip: BigNumber(tip).times(DOT_DECIMAL_PLACES).toNumber()
	});
	const payload = api.createType('ExtrinsicPayload', signer.toPayload(), { version: signer.version });
	const signingInputs = { ...payload.toHuman() };
	signingInputs.tip = tip;
	return { 
		payload: payload.toHex(),
		signingInputs
	};	
};

// eslint-disable-next-line no-unused-vars
methods.prepareTransfer = async (fromAddress, toAddress, amount, { tip } = {}) => {
	await api.isReadyOrError;
	amount = BigNumber(amount).times(DOT_DECIMAL_PLACES).toNumber();

	const { availableBalance } = await api.derive.balances.all(toAddress);
	const transaction = availableBalance / DOT_DECIMAL_PLACES > 0 ? 
		api.tx.balances.transfer(toAddress, amount).toHex() : api.tx.balances.transferKeepAlive(toAddress, amount).toHex();
	const { payload, signingInputs } = await prepareSignerPayload(fromAddress, transaction, tip);
	const fee = await methods.estimateFee(transaction);

	return {
		transaction,
		fee,
		payload,
		signingInputs,
		metadata: api.runtimeMetadata.toHex()
	};
};

methods.prepareStakeAndDelegate = async (fromAddress, delegations, amount, { tip } = {}) => {
	await api.isReadyOrError;
	amount = BigNumber(amount).times(DOT_DECIMAL_PLACES).toNumber();
	let validators = (await api.query.staking.nominators(fromAddress)).toHuman()?.targets || [];
	delegations.forEach((i) => {
		if (!validators.includes(i)) validators.push(i);
	});
	const controller = (await api.query.staking.bonded(fromAddress)).toHuman();
	const bond = !controller ? api.tx.staking.bond(fromAddress, amount, 0) : api.tx.staking.bondExtra(amount);
	const transaction = api.tx.utility.batchAll([
		bond,
		api.tx.staking.nominate(validators)
	]).toHex();
	const { payload, signingInputs } = await prepareSignerPayload(fromAddress, transaction, tip);
	const fee = await methods.estimateFee(transaction);
	return {
		transaction,
		fee,
		payload,
		signingInputs,
		metadata: api.runtimeMetadata.toHex()
	};
};

// eslint-disable-next-line no-unused-vars
methods.prepareStake = async (fromAddress, toAddress, amount = 0) => {
	await api.isReadyOrError;
	amount = BigNumber(amount).times(DOT_DECIMAL_PLACES).toNumber();
	const controller = (await api.query.staking.bonded(fromAddress)).toHuman();
	const transaction = !controller ? api.tx.staking.bond(toAddress, amount, 0).toHex() : api.tx.staking.bondExtra(amount).toHex();
	const fee = await methods.estimateFee(transaction);
	const { payload, signingInputs } = await prepareSignerPayload(fromAddress, transaction);

	return {
		transaction,
		fee,
		payload,
		signingInputs,
		metadata: api.runtimeMetadata.toHex()
	};
};

// eslint-disable-next-line no-unused-vars
methods.prepareUnstake = async (accountId, amount, { tip } = {}) => {
	await api.isReadyOrError;
	amount = BigNumber(amount).times(DOT_DECIMAL_PLACES).toNumber();
	const transaction = api.tx.staking.unbond(amount).toHex();
	const fee = await methods.estimateFee(transaction);
	const { payload, signingInputs } = await prepareSignerPayload(accountId, transaction, tip);

	return {
		transaction,
		fee,
		payload,
		signingInputs,
		metadata: api.runtimeMetadata.toHex()
	};
};

// eslint-disable-next-line no-unused-vars
methods.prepareDelegations = async (fromAddress, delegations) => {
	await api.isReadyOrError;
	const validators = (await api.query.staking.nominators(fromAddress)).toHuman()?.targets || [];
	const newValidators = delegations.map(row => row.address);
	newValidators.forEach((i) => {
		if (!validators.includes(i)) validators.push(i);
	});
	const transaction = api.tx.staking.nominate(validators).toHex();
	const fee = await methods.estimateFee(transaction);
	const { payload, signingInputs } = await prepareSignerPayload(fromAddress, transaction);

	return {
		transaction,
		fee,
		payload,
		signingInputs,
		metadata: api.runtimeMetadata.toHex()
	};
};

// eslint-disable-next-line no-unused-vars
methods.prepareDelegation = async (fromAddress, toAddress) => {
	await api.isReadyOrError;
	const validators = (await api.query.staking.nominators(fromAddress)).toHuman()?.targets || [];
	if (!validators.includes(toAddress)) validators.push(toAddress);
	const transaction = api.tx.staking.nominate(validators).toHex();
	const fee = await methods.estimateFee(transaction);
	const { payload, signingInputs } = await prepareSignerPayload(fromAddress, transaction);

	return {
		transaction,
		fee,
		payload,
		signingInputs,
		metadata: api.runtimeMetadata.toHex()
	};
};

// eslint-disable-next-line no-unused-vars
methods.prepareUndelegation = async (fromAddress, delegations, { tip } = {}) => {
	await api.isReadyOrError;
	const validators = (await api.query.staking.nominators(fromAddress)).toHuman()?.targets || [];
	const newValidators = validators.filter(i => !delegations.includes(i));
	const transaction = api.tx.staking.nominate(newValidators).toHex();
	const fee = await methods.estimateFee(transaction);
	const { payload, signingInputs } = await prepareSignerPayload(fromAddress, transaction, tip);

	return {
		transaction,
		fee,
		payload,
		signingInputs,
		metadata: api.runtimeMetadata.toHex()
	};
};

methods.prepareClaimUnstaked = async (address, { tip } = {}) => {
	await api.isReadyOrError;
	let { redeemable } = await api.derive.staking.account(address);
	redeemable = redeemable / DOT_DECIMAL_PLACES;
	if (redeemable === 0) throw new Error('You don\'t have an unstaked balance');

	const transaction = api.tx.staking.withdrawUnbonded(0).toHex();
	const fee = await methods.estimateFee(transaction);
	const { payload, signingInputs } = await prepareSignerPayload(address, transaction, tip);

	return {
		transaction,
		fee,
		payload,
		signingInputs,
		metadata: api.runtimeMetadata.toHex()
	};
};

methods.prepareClaimReward = async (address) => {
	await api.isReadyOrError;
	const currentEra = (await api.query.staking.activeEra()).toJSON().index;
	// eslint-disable-next-line no-unused-vars
	const eras = Array(10).fill().map((_, idx) => api.createType('EraIndex', (currentEra - 10) + idx));
	
	let [rewards] = await api.derive.staking._stakerRewards([address], eras, true);

	let unclaimEras = rewards.filter(i => i.isEmpty === true).map(i => i.era.toJSON());
	
	if (!unclaimEras.length > 0) throw new Error('You don\'t have any rewards');
	let validators = new Set();

	if (unclaimEras.length === 10) {
		// eslint-disable-next-line no-unused-vars
		let prevDecade = Array(10).fill().map((_, idx) => api.createType('EraIndex', (currentEra - 20) + idx));
		let [prevRewards] = await api.derive.staking._stakerRewards([address], prevDecade, true);
		rewards.push(...prevRewards);
		unclaimEras.push(...prevRewards.filter(i => i.isEmpty === true).map(i => i.era.toJSON()));
	}

	rewards.forEach((i) => {
		Object.keys(i.validators).forEach(j => validators.add(j));
	});

	if (validators.size === 0) throw new Error('There are no available rewards');

	const payoutCalls = [];

	unclaimEras.forEach((i) => {
		validators.forEach((js) => {
			payoutCalls.push(api.tx.staking.payoutStakers(js, i));
		});
	});

	const transaction = api.tx.utility.batch(payoutCalls).toHex();
	const fee = await methods.estimateFee(transaction);
	const { payload, signingInputs } = await prepareSignerPayload(address, transaction);

	return {
		transaction,
		fee,
		payload,
		signingInputs,
		metadata: api.runtimeMetadata.toHex()
	};
};

methods.prepareListOfValidators = async (address) => {
	await api.isReadyOrError;
	return { validators: (await api.query.staking.nominators(address))?.toHuman()?.targets || [] };
};

methods.prepareListOfNodes = async () => {
	await api.isReadyOrError;
	const era = await api.query.staking.activeEra();
	const nodes = {
		addresses: [],
		result: {}
	};
	await Promise.all((await api.query.staking.erasValidatorPrefs.entries(era.toHuman().index)).map(async function (chunk) {
		try {
			if (chunk[1].toHuman().blocked === false) {
				nodes.addresses.push(chunk[0].toHuman()[1]);
				nodes.result[chunk[0].toHuman()[1]] = { fee: parseFloat(chunk[1].toHuman().commission) };
			}
			chunk = null;
		} catch (e) {
			console.error(e);
		}
	}));
	
	await Promise.all(nodes.addresses.map(async function (chunk) {
		try {
			let name = (await api.query.identity.identityOf(chunk))?.toHuman()?.info?.display.Raw || null;
			if (isHex(name)) name = hexToString(name);
			nodes.result[chunk].name = name;
			chunk = null;
		} catch (e) {
			console.error(e);
		}
	}));
	nodes.addresses = null;
	return nodes.result;
};

methods.estimateFee = async (hex_tx, sender = '1HYMQzjmZDNgEWUvEVXkEw7hLNVbeg7byUy5N9GnvqKMPGm') => {
	await api.isReadyOrError;
	const tx = await api.tx(hex_tx).paymentInfo(sender);
	return BigNumber(parseFloat(tx.partialFee.toHuman())).div(1000).times(1.1).toNumber();
};

methods.signAndSendTransaction = async function (signer, signature, unsignedTx, payload) {
	await api.isReadyOrError;
	const tx = api.tx(unsignedTx);
	tx.addSignature(signer, signature, payload);
	return { hash: await tx.send() };
};

// добавить сохранение результата в базу
// eslint-disable-next-line no-unused-vars
methods.sendTransaction = async (address, signedTransaction, keyType = null) => {
	await api.isReadyOrError;
	return { hash: await api.tx(signedTransaction).send() };
};

methods.getDelegationBalanceInfo = async (address) => {
	await api.isReadyOrError;
	const { vestedClaimable, availableBalance } = await api.derive.balances.all(address);
	const { redeemable, stakingLedger, unlocking } = await api.derive.staking.account(address);
	
	let { index: activeEra, start: startDate } = (await api.query.staking.activeEra()).toHuman();
	startDate = new Date(parseInt(startDate.replace(/,/g, '')));
	activeEra = parseInt(activeEra);
	
	let frozenBalance = 0;
	if (unlocking) {
		unlocking.forEach((i) => {
			frozenBalance += i.value / DOT_DECIMAL_PLACES;
		});
	}

	let frozen = [];
	if (stakingLedger.unlocking) {
		frozen = stakingLedger.unlocking.map(i => { 
			const eraDifference = parseInt(i.toHuman().era) - activeEra;
			return {
				amount: i.value / DOT_DECIMAL_PLACES,
				date: startDate.getTime() + eraDifference * APPROX_ERA_DURATION + parseInt(APPROX_ERA_DURATION / 2)
			};
		});
	}

	if (frozen.length) {
		frozen.sort((a, b) => a.date > b.date ? 1 : -1);
	}

	return {
		mainBalance: availableBalance / DOT_DECIMAL_PLACES,
		delegatedBalance: stakingLedger.total / DOT_DECIMAL_PLACES, 
		adding: [],
		stake: stakingLedger.active / DOT_DECIMAL_PLACES,
		frozenBalance,
		frozen,
		unstake: redeemable / DOT_DECIMAL_PLACES, // remove it later
		rewards: vestedClaimable / DOT_DECIMAL_PLACES
	};
};
