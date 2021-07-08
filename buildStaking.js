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
