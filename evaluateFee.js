methods.estimateFee = async (hex_tx, sender = '1HYMQzjmZDNgEWUvEVXkEw7hLNVbeg7byUy5N9GnvqKMPGm') => {
	await api.isReadyOrError;
	const tx = await api.tx(hex_tx).paymentInfo(sender);
	return BigNumber(parseFloat(tx.partialFee.toHuman())).div(1000).times(1.1).toNumber();
};
