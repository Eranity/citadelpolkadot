const assert = require('assert');

global.offCurrency = true;
global.isTest = true;

const currency = 'polkadot';

const POLKADOT = require('../../../connectors/' + currency);

describe.skip('connectors/' + currency + ' -> getOneBlock', function () {

	it('Transfer', async function () {
		this.timeout(100000);
		// https://polkadot.subscan.io/extrinsic/0x016db32a11169b39b996ee6a48c0715b38a94e388f31cd3582abd1462a9cf903
		const hash = '0x016db32a11169b39b996ee6a48c0715b38a94e388f31cd3582abd1462a9cf903';
		const blockNumber = '4295842';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'transfer',
					hash,
					date: '2021-03-22T07:28:36.000Z',
					from: '16UhP6nc95BWMwByxySxrbPCJk8T4UAVxiSCGC3QhRFM6tXQ',
					to: '16Xuv8TZpqSP9iSxquSJ9CQDfnJink7tFFNg8YYLqE5DiXkn',
					type: 'transfer',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -990.71064478,
					deltaTo: 990.71064478,
					blockNumber
				},
				{
					originalOpType: 'deposit',
					hash,
					date: '2021-03-22T07:28:36.000Z',
					from: '16UhP6nc95BWMwByxySxrbPCJk8T4UAVxiSCGC3QhRFM6tXQ',
					to: '12eDfoz2ufNGpPzDE8KTKbFMZpfPC8w4T11xqC8GrXBpFmsr',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.0157,
					deltaTo: 0.0157,
					blockNumber
				}
			]
		);
	});

	it('TransferKeepAlive - Transfer', async function () {
		this.timeout(100000);
		// https://polkadot.subscan.io/extrinsic/0x850ff0e20dc2695f78170efaeb0edc711a85a11f41d4dbde16e31b1601322efc
		const hash = '0x850ff0e20dc2695f78170efaeb0edc711a85a11f41d4dbde16e31b1601322efc';
		const blockNumber = '4256296';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'transfer',
					hash,
					date: '2021-03-19T13:32:12.000Z',
					from: '12MfdWi3X92hhor4QhUSLHCnG36wEywwiFFsovK7GU96EKtB',
					to: '15kUt2i86LHRWCkE3D9Bg1HZAoc2smhn1fwPzDERTb1BXAkX',
					type: 'transfer',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -9999.7742,
					deltaTo: 9999.7742,
					blockNumber,
				},
				{
					originalOpType: 'deposit',
					hash,
					date: '2021-03-19T13:32:12.000Z',
					from: '12MfdWi3X92hhor4QhUSLHCnG36wEywwiFFsovK7GU96EKtB',
					to: '162BjyXHNoFfuUETP39d7fj4LfLiWMCLZ5SHoH48xEna9VnX',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.0158,
					deltaTo: 0.0158,
					blockNumber
				}
			]
		);
	});

	it('Bond - stake', async function () {
		this.timeout(100000);
		// https://polkascan.io/polkadot/transaction/0x91864a0b3783fd96e2234264e65a4255a2af7d1d2340c4bd6caa5676e01cbc5c
		const hash = '0x91864a0b3783fd96e2234264e65a4255a2af7d1d2340c4bd6caa5676e01cbc5c';
		const blockNumber = '2784713';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'unbonded',
					hash: '0x91864a0b3783fd96e2234264e65a4255a2af7d1d2340c4bd6caa5676e01cbc5c',
					date: '2020-12-06T20:35:48.000Z',
					from: '',
					to: '13bGbuJ47ksvtnfRVJPzPDdcARGZTeZdzU19h6qEqRMWJREh',
					type: 'unstake',
					comment: 15,
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2784713'
				},
				{
					originalOpType: 'treasury',
					hash: '0x91864a0b3783fd96e2234264e65a4255a2af7d1d2340c4bd6caa5676e01cbc5c',
					date: '2020-12-06T20:35:48.000Z',
					from: '13bGbuJ47ksvtnfRVJPzPDdcARGZTeZdzU19h6qEqRMWJREh',
					to: '',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: -0.02064,
					deltaTo: 0.02064,
					blockNumber: '2784713'
				},
				{
					originalOpType: 'deposit',
					hash: '0x91864a0b3783fd96e2234264e65a4255a2af7d1d2340c4bd6caa5676e01cbc5c',
					date: '2020-12-06T20:35:48.000Z',
					from: '13bGbuJ47ksvtnfRVJPzPDdcARGZTeZdzU19h6qEqRMWJREh',
					to: '15DLJZ4ceN58vEgDiQjK8JsSJuLNBqhUnQ6QCY1QNSjrQntm',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: -0.00516,
					deltaTo: 0.00516,
					blockNumber: '2784713'
				},
				{
					originalOpType: 'bond',
					hash: '0x91864a0b3783fd96e2234264e65a4255a2af7d1d2340c4bd6caa5676e01cbc5c',
					date: '2020-12-06T20:35:48.000Z',
					from: '13bGbuJ47ksvtnfRVJPzPDdcARGZTeZdzU19h6qEqRMWJREh',
					to: '',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: -15,
					deltaTo: 0,
					blockNumber: '2784713'
				}
			]
		);
	});

	it('Bond_extra - stake', async function () {
		this.timeout(5000);
		// https://polkascan.io/polkadot/transaction/0x3a37fe62dace657c5686131836c2c5e73c294c8731455f99ad69b0180bf525d1
		const hash = '0x3a37fe62dace657c5686131836c2c5e73c294c8731455f99ad69b0180bf525d1';
		const blockNumber = '2905102';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'unbonded',
					hash: '0x3a37fe62dace657c5686131836c2c5e73c294c8731455f99ad69b0180bf525d1',
					date: '2020-12-15T06:23:36.000Z',
					from: '',
					to: '14FpqUiMJtD8e1PNqhBmnuZQMHKydbGG1hFSdZ8AuKt9jhw7',
					type: 'unstake',
					comment: 8.8442,
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2905102'
				},
				{
					originalOpType: 'treasury',
					hash: '0x3a37fe62dace657c5686131836c2c5e73c294c8731455f99ad69b0180bf525d1',
					date: '2020-12-15T06:23:36.000Z',
					from: '14FpqUiMJtD8e1PNqhBmnuZQMHKydbGG1hFSdZ8AuKt9jhw7',
					to: '',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: -0.00976,
					deltaTo: 0.00976,
					blockNumber: '2905102'
				},
				{
					originalOpType: 'deposit',
					hash: '0x3a37fe62dace657c5686131836c2c5e73c294c8731455f99ad69b0180bf525d1',
					date: '2020-12-15T06:23:36.000Z',
					from: '14FpqUiMJtD8e1PNqhBmnuZQMHKydbGG1hFSdZ8AuKt9jhw7',
					to: '13EWPQ17GJTdBvA4FoAgq9mf8nwsH4cpahjn7fuAG3Xed72q',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: -0.00244,
					deltaTo: 0.00244,
					blockNumber: '2905102'
				},
				{
					originalOpType: 'bondExtra',
					hash: '0x3a37fe62dace657c5686131836c2c5e73c294c8731455f99ad69b0180bf525d1',
					date: '2020-12-15T06:23:36.000Z',
					from: '14FpqUiMJtD8e1PNqhBmnuZQMHKydbGG1hFSdZ8AuKt9jhw7',
					to: '',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: -8.8442,
					deltaTo: 0,
					blockNumber: '2905102'
				}
			]
		);
	});

	it('Nominate - stake', async function () {
		this.timeout(5000);
		// https://polkascan.io/polkadot/transaction/0x2d96cc3ab2c6be9e8d0d0c7e505884120e4fceb4436bcfe50095a55078007b2e
		const hash = '0x2d96cc3ab2c6be9e8d0d0c7e505884120e4fceb4436bcfe50095a55078007b2e';
		const blockNumber = '2784742';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'treasury',
					hash,
					date: '2020-12-06T20:38:42.000Z',
					from: '13bGbuJ47ksvtnfRVJPzPDdcARGZTeZdzU19h6qEqRMWJREh',
					to: '',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.02528,
					deltaTo: 0.02528,
					blockNumber
				},
				{
					originalOpType: 'deposit',
					hash,
					date: '2020-12-06T20:38:42.000Z',
					from: '13bGbuJ47ksvtnfRVJPzPDdcARGZTeZdzU19h6qEqRMWJREh',
					to: '1cFV5Z8xgsRGE3JwfvK54F9mMTWvunoyRA7YADk2by33xtp',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.00632,
					deltaTo: 0.00632,
					blockNumber
				},
				{
					originalOpType: 'nominate',
					hash,
					date: '2020-12-06T20:38:42.000Z',
					from: '13bGbuJ47ksvtnfRVJPzPDdcARGZTeZdzU19h6qEqRMWJREh',
					to: '16DKyH4fggEXeGwCytqM19e9NFGkgR2neZPDJ5ta8BKpPbPK',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber
				},
				{
					originalOpType: 'nominate',
					hash,
					date: '2020-12-06T20:38:42.000Z',
					from: '13bGbuJ47ksvtnfRVJPzPDdcARGZTeZdzU19h6qEqRMWJREh',
					to: '11uMPbeaEDJhUxzU4ZfWW9VQEsryP9XqFcNRfPdYda6aFWJ',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber
				},
				{
					originalOpType: 'nominate',
					hash,
					date: '2020-12-06T20:38:42.000Z',
					from: '13bGbuJ47ksvtnfRVJPzPDdcARGZTeZdzU19h6qEqRMWJREh',
					to: '14QBQABMSFBsT3pDTaEQdshq7ZLmhzKiae2weZH45pw5ErYu',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber
				}
			]
		);
	});

	it('Unbond - unstake', async function () {
		this.timeout(10000);
		// https://polkascan.io/polkadot/transaction/0x4bd5d42210cf9488cb7029182a353182b5ba2c227f5499cb4adaded51ace2cf7
		const hash = '0x4bd5d42210cf9488cb7029182a353182b5ba2c227f5499cb4adaded51ace2cf7';
		const blockNumber = '2791441';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'withdrawn',
					hash,
					date: '2020-12-07T07:52:48.000Z',
					from: '',
					to: '13bGbuJ47ksvtnfRVJPzPDdcARGZTeZdzU19h6qEqRMWJREh',
					type: 'unstake',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 5,
					blockNumber
				},
				{
					originalOpType: 'treasury',
					hash,
					date: '2020-12-07T07:52:48.000Z',
					from: '13bGbuJ47ksvtnfRVJPzPDdcARGZTeZdzU19h6qEqRMWJREh',
					to: '',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.00976,
					deltaTo: 0.00976,
					blockNumber
				},
				{
					originalOpType: 'deposit',
					hash,
					date: '2020-12-07T07:52:48.000Z',
					from: '13bGbuJ47ksvtnfRVJPzPDdcARGZTeZdzU19h6qEqRMWJREh',
					to: '12ivLi4gPZTCLmkaq3CTVHggp7DYv9UW7H4APFnYepWcDaRm',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.00244,
					deltaTo: 0.00244,
					blockNumber
				}
			]
		);
	});

	it('Rebond - stake', async function () {
		this.timeout(10000);
		// https://polkadot.subscan.io/extrinsic/0x6f16c4e55989640f97af67d911502a854a83525616a0480259f3d00833515733
		const hash = '0x6f16c4e55989640f97af67d911502a854a83525616a0480259f3d00833515733';
		const blockNumber = '4296847';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'deposit',
					hash,
					date: '2021-03-22T09:09:06.000Z',
					from: '14yTQGoQ5H6aF9S2J7MbhLuZ8bpbHa2oXeszkDJaUTk8h7ko',
					to: '1UMgfwDQU3W5MCTmwQ1VQn6TDUK6GxUGc61HLCEZppqZ5MW',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.0123,
					deltaTo: 0.0123,
					blockNumber
				},
				{
					originalOpType: 'rebond',
					hash,
					date: '2021-03-22T09:09:06.000Z',
					from: '14yTQGoQ5H6aF9S2J7MbhLuZ8bpbHa2oXeszkDJaUTk8h7ko',
					to: '',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -60,
					deltaTo: 60,
					blockNumber
				}
			]
		);
	});

	it('Set_payee - stake', async function () {
		this.timeout(10000);
		// https://polkadot.subscan.io/extrinsic/0xbacc356bf768a32b9981d9622078b8243f7e149e49fb722e1e5c17a49a9f2654
		const hash = '0xbacc356bf768a32b9981d9622078b8243f7e149e49fb722e1e5c17a49a9f2654';
		const blockNumber = '4296794';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'deposit',
					hash,
					date: '2021-03-22T09:03:48.000Z',
					from: '1537C6dWQktRC3VMvREcLKtezrmQWuawNAV6aTHSh8t5DNNN',
					to: '1zugca3sakAjzRV6XHNqb4aZUhSwTTm318o7spZytyu96qN',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.0118,
					deltaTo: 0.0118,
					blockNumber
				},
				{
					originalOpType: 'setPayee',
					hash,
					date: '2021-03-22T09:03:48.000Z',
					from: '1537C6dWQktRC3VMvREcLKtezrmQWuawNAV6aTHSh8t5DNNN',
					to: '',
					type: 'unsupported',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber
				}
			]
		);
	});

	it('Validate - stake', async function () {
		this.timeout(10000);
		// https://polkadot.subscan.io/extrinsic/0xd93d2bd4d195c3aca8f2989741dd50966e2bbe7569e3931fb4fbf9d1c0932d6a
		const hash = '0xd93d2bd4d195c3aca8f2989741dd50966e2bbe7569e3931fb4fbf9d1c0932d6a';
		const blockNumber = '4296965';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'deposit',
					hash,
					date: '2021-03-22T09:20:54.000Z',
					from: '133GbdqxEmDxhTKSaTxEu8sx9mViidWH9XZMWMakt1jfQywv',
					to: '13Yggarv9or3jpKpt51RjtqSHFhidHPS2QpQbrzLiSJGmw2x',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.0122,
					deltaTo: 0.0122,
					blockNumber
				},
				{
					originalOpType: 'validate',
					hash,
					date: '2021-03-22T09:20:54.000Z',
					from: '133GbdqxEmDxhTKSaTxEu8sx9mViidWH9XZMWMakt1jfQywv',
					to: '',
					type: 'unsupported',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber
				}
			]
		);
	});

	it('Payout_stakers - rewards', async function () {
		this.timeout(10000);
		// https://polkadot.subscan.io/extrinsic/0xe5e454f0bb235998ab1b1a70bf4f29d34551961962659681e2da4438da3b106e
		const hash = '0xe5e454f0bb235998ab1b1a70bf4f29d34551961962659681e2da4438da3b106e';
		const blockNumber = '4296027';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13giQQe5CS4AAjkz1roun8NYUmZAQ2KYp32qTnJHLTcw4VxW',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 25.3635091962,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13L1BQzQtZR51A21uXX6EgztVzsD5yD8QxLbDsGgtqyFWy7t',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 37.931384646,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '1X41ubzrHKZBwktcKVQt3icRzE4728vU3Z32nX6RffpCLEY',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.2121550717,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13C8RThC7p2UVprH3MSw8UkwigGqVkCEi1Q13torD47uTyga',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 1.2268869815,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '1GkEMeenjYqpQh21eNb1DbqSEqjQGi5Gz1MEm7hEsH6nm8Z',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 1.9021570012,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '12sbm9DxAUeZSzrz5oTuA3k4jXFDVbu8XYiNo1GKZCyjf5Qo',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.5261267353,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '16UVfiVCP5NxccF9W7U24PsDT6aZyDe13ZJRf8k6jm8dSeUU',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1852356477,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13dRn2d8krazuzxCJ7Gd3RPuDAkC115D4URkxW8MhnU3SaJe',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.0800416233,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '14WsPxq243FDpWWFwwU7VnZ8ozBPgVGJsRgnZsuz2hDDe43X',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.7702932085,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '15dbJ5c36bjAD3BKLCKTeiGxrg31CFEbhwjhFgWGQiBMV2et',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.2054297255,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '132i5CTGcnhHc4TNHsvpTcJKnzoc1rRG6qMQDRSTLBa1kSxe',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.0952749178,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13bDBiLJc8zngwTbwoPnexP8rDho8sPLHAVUHEJkniJGdr5u',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 2.961524481,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13SWVanbVn3M3cyVMUgrE3RDjoSzVi13eFTSY2nBg4wYcrcs',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 1.6939016792,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '16JBJJEXfs4jXmJ8nqceCcXSGMEZwuYJRkGQM6An7nHaUUSJ',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.7137066606,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13ETBT4j5iUqGjwAjVdoYzA1rzxQnexH7mgjhSTNnpY35iqd',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 2.8450075712,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '14oXMCp1DQXWRFUfjhxJffWhu8uaRQBx9tue8yPKeg9mjmGC',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.0788641547,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '12RBgYMKaoEUDuw9xoA8zDU9zjPkLyBQcnCdzFzk7Dr35D1i',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.3088624668,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '122G9tyuMyEniNYhyZPWtqZt6PmfMerw8or3kbAHAzTB38CF',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.2503334238,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13Ej6xZ3f4gAqguYnG9WbsAfYTpT3f256rPVh3xiySb8oKdE',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1554643883,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13193JNRvjTPkmVM8o1heSQYyR66ikzLxWXVFocQ1FgUSzz6',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.2329075451,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13pdWF75oKKzfyAVFCC1KTkpFqerPjiCi9315BCQ5nt892As',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 80.9168882745,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '14kdXQv3dj22aSWz5cFqT4tM7kq3ge8T4vUbrQtnuZYHAg8u',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.4177225511,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '12D5Qa9oJXqHMMR5xE7nWuVC9UHB72g7o6kgdMxFAyphDekd',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.220159562,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13bV8tiGec7PmE1WpJ6zeTJF5rf4LY7u475oFBsGGxCY7vjT',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.3859259802,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '15nV3NFjFV2zBCvyWBckUPNnEYX9qYsCw1x8C1hiEnzkunij',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.2319350675,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '14DsbQ2up6Rmi6fMpsemmkHezL7YH5g5zp7CxjkU9pdmrdR7',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 1.6297870401,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '133ufr8xAHRDR5F7oBd9hoBjT9oBpBku7pQ6AhF2rnp9hfnJ',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1168063571,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '12zBp1eyBDcGtHhxEw4PUo8idHQw7ozm6DzTX1ejPrdwvW7b',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1109124546,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '12UipDJytUr2VzRobSH1sk8PUMz6GE5SPoaA2ektG9VQpwwD',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.0887988407,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '14j8dCxBR8dPQfBtNMSum6TpwEpKDvUPpaP1y8jSvEWMpWsH',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 3.8259864756,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '124bG81DJUwnf3TG2rmhjsQ3SrdLRt7fS8Ck9cetjNgtndDq',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 84.2031833474,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '16k486kCBfSYLpQheL1a62F9d5NBMJYuuHuEMBL1FcQVAHdS',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1163635765,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '15dFM6VeMA3rBnR2EEW7rxYc9XrnTj1JSSN2GqsMhi1sARsv',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1188816865,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13uEWujPHTYdF6AkXv77cNC7nMf87kwdpY2wyunjhzqvppwL',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.5017934783,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '14cvgSFpmtdLQC2zvMR4ifg4uvo8z7bZrLTvh2UKQgSpHPgE',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 1.9089528643,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '12r4u5tg39BHMCkbZXi1oifXZC5cnZ1Hae7xmWp6srmo928T',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1189128451,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13xF1aY4aqPQN591bmAGS4qBjZMdG3vjzT3KoZrKG9wL9Ude',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.3085410409,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '1xh2uVjtiE6t8BCdG67xxQpgwifpogzTdQ9pbw9vhujsXNN',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 126.01661214,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '12fCJg27i47KBy3j89fs5qqPo5WrUhPARzYcfWA7KsXdzGMe',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.4972664561,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '164pGQ81VHuts6F47Mku4zV4PTj8CBZXW4Mp9nQ9RjtCBHZT',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.0897376997,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '1TQdTUehi4tU41qoRdVUaSiruLHs9vsZ4xzgSiMbV6kQXhP',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1530241749,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '16FQKwZEym79LGCVBrDUQpjyT2ePcWJL6yTURhXBdEWbQ2Mf',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.5263243467,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '12oZr8aKtgpkZVg4CCFo6pspFU4c2bGAUQzJ7EsqRZrGYy2c',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1221049656,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '15qunVeyLEybbNzwhG9Zo4Xz8dtbzc2r58eydd31M3wiz2y3',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 83.8321667759,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13BX4S7WUCyeiqtXJXFrtxRqcsnj3DTxTfT53LgtPSSaNBgX',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.2576089659,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '112Ff1JZ1svbk3Sxe42jXgngc1QsXfX2YemRjQDos7Tx1NXS',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1381147662,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '149BXPZ3Jk2vfwQg9ADxgxT21bAyrEzK4mmmE2idHhZpZ8z7',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 3.7929353595,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '15Y8wejd9ZcQxL5mCBeratbH6JjEde4UYiGSkt9jhgNqYEFY',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 31.6488297696,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '12xcgc3dM86vZzLrgFc1GvHAj7cZCDHRkoHXoTcc52FaX1tt',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 10.620253117,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '12FryyGW5fFXRgyRAhABnuzK5Cskh4hYXXpTiuxeM84HCTAL',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 22.7576162566,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '1MiPcSWQNtBTHZrhMK5vDDEb1jc1mjAXLnEUSjTUPAME2qk',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.0922541697,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13YCukrCvHxi1KgGo17qVTB2XLvEjEHg49tWFmXxMtxtV8TH',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.2181686889,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '14WUNRjtr6GGxLvFb48teTy1tjRrMtvLspMsBNEkmFYu5CqK',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.3837251963,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '1nDoVXGWy2d62iEJB9VAnoBKgK4KsofwAa9Hgz4SYvkfG5a',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1139266429,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '164MWzF7w1hUuCjLwa7Vd3wY2hhtEGRYFSmaWZZuPKpTJFgj',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.0985547745,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '1pVi5StJVNg8A16KHZ6c4rJHFgv69SCESsoMwqmK8jJmf5Q',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 77.5470732904,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '1A1FDjEmS1SZp1NdLtumoY4SZKdssJGM1Mvj11sXkW5nNeR',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 80.8463442964,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '15KLU6v8zy5hrpUnM5Y2ad9NH3FMKezvysqs6h2PC3pt5wBr',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.3726974981,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '16cHFuNUfJ44KMLNdGwBT2w6mW4PLaf3cz7NSaso2qofshrS',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.0834198757,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '16FyqbgcvHrQ8bQb9oQY69BnG9FrF2hV6P2GfouDP3vobZzf',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.4090014121,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '1hCj6GNvu7UEhs1ECXSdWPuzkpRaFMnDbjj6FLmw3d5MUP1',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.4584304927,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '138edFs37VJjyodCUqg6aKvBYaGRR2HK5xuaZ6cb6mUq1aeP',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 4.2081635796,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13Be2vctcaJzCfhoyrAU9C788LobFKmEAmNLcma5Mvw1mHbL',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1907605663,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '16LMKvNidtjgfWs6XdvnVPgBMmNvkANY4WULHVGC5BDAsSjF',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.0913915674,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '1qLT3GYX7ZQXtNK3my2x2nTasPdLE37MUgkEs8DjM8xne9a',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1886565382,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '14dut6zGgdVmKijePZzrQAy2gZ6FmMDmzzp7VqjzPV9E4ujR',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 3.1045705118,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '1emUwFejpatQSfzQuhc4B8ZmnKEpjs5yfP8Pkk88Yy92wFQ',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 25.3041691663,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '16fdd81Q5Nv79hxRjeSw2Q6vDXBX1MNpVaNeFxNDnf1v9k8B',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.095544686,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '16BwNvhuLWfAr6vYcxEWA4arty4qxrrUQuYzwWbkRwGbHXeR',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.0961965575,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '15t23acB8s8M68JhGuiSArGBgcNMdeyE9K25r9f6ExuYpKhn',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1775304443,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '14gguzb1QTHioxfofVFgnbmr4iMDc5CE25Lr4BNAt12GyfZC',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.3920535725,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '14wvKW6iH5S7ZnDxnxBhTKcm1RRBAbMmEgg1ocBCaFt5qHh1',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 1.8964672698,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '14kC8tCzZKvWLdS7Sxg4pq4LT3hUuS5x4jkFsESRSEb1NCxy',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.3021797588,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '15Xn4cUKFBPg2W743j7JrkjXRQ4yFiPKzN5UW19xR9FYySWw',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.283084433,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '167nTJToRtZK1Ji73sr3Js8bmcbkzhT3GLt7aVG17gQqFqSS',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 7.7565536424,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '15zaaqAvs9vM4EwFJYDsLW74eYYYkf7WGWjx7yGHw6AYoF5N',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 1.6573345567,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '14DqBhpDToP5EibUFa7p12pyapzvdicpr8aCuBkB7jc3bnsj',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.1099949147,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '15VRn1X17Kb3mY4LHZFCLdsbggGpatJXnW2287Q7sAs86MZk',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.2379519647,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '16SWh9HPLjg5X3auiJfPV2Yh6bwdUV7wWPFHzYBzzXbbGZRa',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 1.6707647499,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '15ck8j4BPiPRmTme1e7Tw8gPV9EGmDeYUVGg7RvBEZxuiaw2',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.0789633704,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '1KhVv3sjfuiXwc4Aqa4HJQAio8PAD2mQds1amRuWKnxZu4w',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.9423626914,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '13ogfdG6ZF6NWuKKUBZztx6FhSMHHt4cQuypqnjB4mbBUa6a',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 3.8318697186,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '12PsXxWv2kksqYJFeqsCgS7vYdDWTw8JHBQSWrdK4Zc5KyN',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.0827073268,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '14wkncLS98WwLmX1sggPq1XrYpQNN1Si7dwugg6pqAioL3aA',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.096092422,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '12pyej2jhwzGjtNUgXCvyUjYnVNupTKYhZndEDDy3QETymJR',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0.3722145392,
					blockNumber
				},
				{
					originalOpType: 'reward',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '',
					to: '1xnfqp4JaNGVEN7uoinGSVKztsygrbCnG4tPCXnNb9KDhRt',
					type: 'reward',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 98.1194645121,
					blockNumber
				},
				{
					originalOpType: 'deposit',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '13bDBiLJc8zngwTbwoPnexP8rDho8sPLHAVUHEJkniJGdr5u',
					to: '1dGsgLgFez7gt5WjX2FYzNCJtaCjGG6W9dA42d9cHngDYGg',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.0153000005,
					deltaTo: 0.0153000005,
					blockNumber
				},
				{
					originalOpType: 'payoutStakers',
					hash,
					date: '2021-03-22T07:47:06.000Z',
					from: '13bDBiLJc8zngwTbwoPnexP8rDho8sPLHAVUHEJkniJGdr5u',
					to: '13giQQe5CS4AAjkz1roun8NYUmZAQ2KYp32qTnJHLTcw4VxW',
					type: 'unsupported',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber
				}
			]
		);
	});

	it('Withdraw_unbonded - stake', async function () {
		this.timeout(10000);
		// https://polkadot.subscan.io/extrinsic/0x806ee2dfb0bc7e28eec02a4bdf798bdf5013a2c57cb64fffa14bd565ef051117
		const hash = '0x806ee2dfb0bc7e28eec02a4bdf798bdf5013a2c57cb64fffa14bd565ef051117';
		const blockNumber = '4296992';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'deposit',
					hash: '0x806ee2dfb0bc7e28eec02a4bdf798bdf5013a2c57cb64fffa14bd565ef051117',
					date: '2021-03-22T09:23:36.000Z',
					from: '12eYP7roeT2UkZxo2MJknC15DW3taqi1bqnGahA8RDzGqhiY',
					to: '16SxHe93PgkkfCHouc4mtCrzbirN1Ba8nCLHatNm66nXtEJH',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: -0.0121,
					deltaTo: 0.0121,
					blockNumber: '4296992'
				}
			]
		);
	});

	it('Chill - unstaking', async function () {
		this.timeout(10000);
		// https://polkadot.subscan.io/extrinsic/0x73dbd226f4b777b63aade10ee9a425c741014b896ff7ab8f937514e51d80eb17
		const hash = '0x73dbd226f4b777b63aade10ee9a425c741014b896ff7ab8f937514e51d80eb17';
		const blockNumber = '4252779';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'deposit',
					hash,
					date: '2021-03-19T07:39:54.000Z',
					from: '135Kr5LGRU3A8oeutrZm2Na4pDtiKY1SVhxUY7AniKJBsvHm',
					to: '15yyudqwLHT6VcKdEug98wt1rCbyg5TBvr6ikakL4rNVAYXf',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.0117,
					deltaTo: 0.0117,
					blockNumber: '4252779'
				},
				{
					originalOpType: 'chill',
					hash,
					date: '2021-03-19T07:39:54.000Z',
					from: '135Kr5LGRU3A8oeutrZm2Na4pDtiKY1SVhxUY7AniKJBsvHm',
					to: '',
					type: 'unstake',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber
				}
			]
		);
	});

	it('Batch - multi', async function () {
		this.timeout(5000);
		// https://polkascan.io/polkadot/transaction/0x0916aa08094eb1a4d2ac4ee4d0cfc4d68ea19919ff5f0c6a0b7762784ea412f0
		const hash = '0x0916aa08094eb1a4d2ac4ee4d0cfc4d68ea19919ff5f0c6a0b7762784ea412f0';
		const blockNumber = '2905111';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					blockNumber,
					comment: '',
					currency,
					date: '2020-12-15T06:24:30.000Z',
					deltaFrom: -3,
					deltaTo: 3,
					from: '1exaAg2VJRQbyUBAeXcktChCAqjVP9TUxF3zo23R2T6EGdE',
					hash,
					isCanceled: false,
					originalOpType: 'transfer',
					to: '1EPqnxbyifkLSQSyHZCameQdYCNkPnZ4B3CgttWwRCa8aDp',
					type: 'transfer'
				},
				{
					originalOpType: 'treasury',
					hash,
					date: '2020-12-15T06:24:30.000Z',
					from: '1exaAg2VJRQbyUBAeXcktChCAqjVP9TUxF3zo23R2T6EGdE',
					to: '',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.0128,
					deltaTo: 0.0128,
					blockNumber
				},
				{
					originalOpType: 'deposit',
					hash,
					date: '2020-12-15T06:24:30.000Z',
					from: '1exaAg2VJRQbyUBAeXcktChCAqjVP9TUxF3zo23R2T6EGdE',
					to: '121gZtuuG6sq3BZp1UKg8oRLRZvp89SAYSxXypwDJjaSRJR5',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.0032,
					deltaTo: 0.0032,
					blockNumber
				}
			]
		);
	});

	it('Batch_all multi', async function () {
		this.timeout(5000);
		// https://polkascan.io/polkadot/transaction/0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86
		const hash = '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86';
		const blockNumber = '2903703';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'unbonded',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '',
					to: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					type: 'unstake',
					comment: 10.0734,
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'treasury',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: -0.05128,
					deltaTo: 0.05128,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'deposit',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '15hkz83sTMouD7GiiWP3SQc5DXaZFumYgJ6bf8Xq3dphPQ4h',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: -0.01282,
					deltaTo: 0.01282,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'bond',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: -10.0734,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '125xj1nYWcVcCM9CnLUydqEmuFwSNTmRybmyK65XWu8RFWK3',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '13gaBDtm7gkyBXuqoYvUC4z7oYSFGBRcX9F4fa4vk3mvh2KX',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '14dTZLAwhcBennygERRS5tXnWVAHq3e12LoCoHrQsmDd4X4H',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '1CHpqr1UKm8MAZZgViAvzombX2AgpQbDf7vJy864FQa55nk',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '1653t723BHhC2krGCFKUUNDQb5sUafy5pZvKVwnwo1oMAMi7',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '14ianQU2g46wntbuJxx6u9cM6s8uvLngW1y9xKCcnejBHdTy',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '16fL6kGX64fQ8cCvRu15idGS1VZnLiCZkkDWQer981ux5FRA',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '13W8fgmJvTZ578FpeQZqVtnPt7YJYV8oF1yXA49LijG7kNaW',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '16JcdktXy1ykqPPtQsu4jrtSg7nBfBxKShe64oLxJkeaEb5h',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '15zDWoFYi5m2VMb9yXeBa8CozgRDGEXoW14WLXPXPXGj9kvi',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '15yiAFuYzks3FGG8cTc2ukw86JCYKrZqKkmStVhTL4hv77XV',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '128xoAmYDMLixg9Dv4sQz3vJnG94Jt1s2hp37PR8CQZMMMfp',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '15uBfpvbPWSUaiLjrgT3H389axNwLkduKA3GB88C1fqbWLpz',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '12LKeuFyyjC94iXpHftt3UVu567ji5WyKE6MvDBDWVJUuuJJ',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				},
				{
					originalOpType: 'nominate',
					hash: '0x962d4fa4201126f9664e131ac84b2058d9a6e463b55fb461cdeaacd01a0cfa86',
					date: '2020-12-15T04:02:42.000Z',
					from: '14TPRFCmRjjYYyTXxpKX9waWPXW2PGXNuNuvxUdvtX9V2zd9',
					to: '15ictvkBL2D3aWxyoqh8roJkRC1tdFw3SCLqjyssjuf6yiC9',
					type: 'stake',
					comment: '',
					isCanceled: false,
					currency: 'polkadot',
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber: '2903703'
				}
			]
		);
	});

	it('Set_identity - identity', async function () {
		this.timeout(10000);
		// https://polkadot.subscan.io/extrinsic/0xf63c486a488d8454fd0b5fe4b29529f4a6f7208068832cd430adb7b98e91bf82
		const hash = '0xf63c486a488d8454fd0b5fe4b29529f4a6f7208068832cd430adb7b98e91bf82';
		const blockNumber = '4283284';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'deposit',
					hash,
					date: '2021-03-21T10:32:06.000Z',
					from: '12CJw9KNkC7FzVVg3dvny4PWHjjkvdyM17mmNfXyfucp8JfM',
					to: '1zugcabYjgfQdMLC3cAzQ8tJZMo45tMnGpivpAzpxB4CZyK',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.0225,
					deltaTo: 0.0225,
					blockNumber
				},
				{
					originalOpType: 'setIdentity',
					hash,
					date: '2021-03-21T10:32:06.000Z',
					from: '12CJw9KNkC7FzVVg3dvny4PWHjjkvdyM17mmNfXyfucp8JfM',
					to: '',
					type: 'unsupported',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: 0,
					deltaTo: 0,
					blockNumber
				}
			]
		);
	});

	it('Failed', async function () {
		this.timeout(5000);
		// https://polkascan.io/polkadot/extrinsic/0x084346cbbd6a6f0b373641055e87cc36d46bc9b36c341a016e322270448450b4
		const hash = '0x084346cbbd6a6f0b373641055e87cc36d46bc9b36c341a016e322270448450b4';
		const blockNumber = '2923427';
		assert.deepEqual(
			(await POLKADOT.getOneBlock({ blockNumber, hash, throws: true })).transactions,
			[
				{
					originalOpType: 'treasury',
					hash,
					date: '2020-12-16T13:06:42.000Z',
					from: '15MrtLcAgfVoeCW1MdP27aAsGiVCqwR89m8RNahkcqwfHho7',
					to: '',
					type: 'fees',
					comment: '',
					isCanceled: false,
					currency,
					deltaFrom: -0.25264,
					deltaTo: 0.25264,
					blockNumber
				},
				{
					blockNumber: '2923427',
					comment: '',
					currency,
					date: '2020-12-16T13:06:42.000Z',
					deltaFrom: -0.06316,
					deltaTo: 0.06316,
					from: '15MrtLcAgfVoeCW1MdP27aAsGiVCqwR89m8RNahkcqwfHho7',
					hash,
					isCanceled: false,
					originalOpType: 'deposit',
					to: '15a9ScnYeVfQGL9HQtTn3nkUY1DTB8LzEX391yZvFRzJZ9V7',
					type: 'fees'
				},
				{
					originalOpType: 'transferKeepAlive',
					hash,
					date: '2020-12-16T13:06:42.000Z',
					from: '15MrtLcAgfVoeCW1MdP27aAsGiVCqwR89m8RNahkcqwfHho7',
					to: '14ShUZUYUR35RBZW6uVVt1zXDxmSQddkeDdXf1JkMA6P721N',
					type: 'transfer',
					comment: '',
					isCanceled: true,
					currency,
					deltaFrom: -38.8,
					deltaTo: 38.8,
					blockNumber
				}
			]
		);
	});

});
