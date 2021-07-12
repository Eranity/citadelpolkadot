const axios = require('axios');
const config = require('../../config');
const api_key = config['nomics.com'].key;
const MarketCapObject = require('./');

module.exports = function (code) {
	const instance = new MarketCapObject(code);
	instance.addStage(async () => {
		let marketCapDataUSD = (await axios.get('https://api.nomics.com/v1/currencies/ticker?key=' + api_key + '&ids=' + code.toUpperCase() + '&interval=1d&convert=USD')).data[0];
		if (marketCapDataUSD) {
			if (marketCapDataUSD.price) {
				instance.priceUsd = marketCapDataUSD.price;
				if (marketCapDataUSD['1d']) {
					instance.priceUsdDelta24 = marketCapDataUSD['1d'].price_change;
					instance.priceUsdDelta24pct = marketCapDataUSD['1d'].price_change_pct * 100;
				}
			} else {
				console.warn('Marketcap', code + ' doesn\'t have price in USD');
			}
			instance.marketCap = marketCapDataUSD.market_cap;
			instance.circulatingSupply = marketCapDataUSD.circulating_supply;
		} else {
			console.warn('Marketcap', code + ' doesn\'t have any data');
		}
		await new Promise(next => setTimeout(next, 1000));
	}).then(() => {
		return instance.addStage(async () => {
			let marketCapDataBTC = (await axios.get('https://api.nomics.com/v1/currencies/ticker?key=' + api_key + '&ids=' + code.toUpperCase() + '&interval=1d&convert=BTC')).data[0];
			if (marketCapDataBTC) {
				if (marketCapDataBTC.price) {
					instance.priceBtc = marketCapDataBTC.price;
					if (marketCapDataBTC['1d']) {
						instance.priceBtcDelta24 = marketCapDataBTC['1d'].price_change;
						instance.priceBtcDelta24pct = marketCapDataBTC['1d'].price_change_pct * 100;
					}
				} else {
					console.warn('Marketcap', code + ' doesn\'t have price in BTC');
				}
			}
		});
	}).then(instance.triggerUpdate.bind(instance));
	return instance;
};
