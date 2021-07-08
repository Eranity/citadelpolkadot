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
