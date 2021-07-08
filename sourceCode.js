const main = require('./main');
const LogBlocks = require('../models/LogBlocks');

main.net = 'polkadot';
// main.earliest_blockNumber =
main.latest_blockNumber = 4358765;
main.nPromises = 30;

const POLKADOT = require('../connectors/polkadot');
main.getOneBlock = async function (blockNumber) {
	//try{}catch(e){}
	let {transactions, block_info} = (await POLKADOT.getOneBlock({blockNumber, throws: true}));
	LogBlocks.create({
		net: main.net,
		blockNumber: block_info.blockNumber,
		originalTxsCount: block_info.originalTxsCount,
		blockDate: block_info.blockDate,
		prepareTime: block_info.prepareTime,
		txsCount: transactions.length,
		parseDate: Date.now()
	});
	return transactions;
};

main.tables = [
	'transactions_polkadot',
];

main.sortByTables = function () {
	return 'transactions_polkadot';
};

main.allowHardReset();

main.run();
