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
