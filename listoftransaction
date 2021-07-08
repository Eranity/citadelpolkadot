import dayjs from 'dayjs'
import * as d3Format from 'd3-format'
import netCurrencyTypes from './storeTypes/netCurrencyTypes'
import { getTransactionUrl } from '@/helpers/transactions-helpers'
import { numberFormatterByCurrency } from '@/helpers/numerals'
import { TRANSACTION, NETWORK, ERC20, SNIP20, BEP20 } from '@/store/types'

const DEFAULT_TABLE_LIMIT = 5
const DEFAULT_TABLE_PAGE_NUMBER = 1
const DEFAULT_TABLE_MAX_PAGE = 6

const DEFAULT_CHART_PERIOD = 'all'
const CURRENT_CURRENCY_FOR_GRAPH = 2

export const namespaced = false

export const state = () => ({
  filter: null,
  transactions: [],
  transactionsQuantity: 0,
  chartData: [],

  chartOptions: {
    step: 10080, // 1 week in minutes
    currency: 'usd', // 'usd', 'btc', 'eur'
    period: DEFAULT_CHART_PERIOD, // Допустимые значения: 1h, 12h, 1d, 3d, 1w, 1m, 3m, 6m, 1y, 2y, 3y, all
    customPeriod: {},
    chartType: 'balance' // 'reward' || 'balance'
  },

  tableOptions: {
    limit: DEFAULT_TABLE_LIMIT,
    page: DEFAULT_TABLE_PAGE_NUMBER,
    maxPage: DEFAULT_TABLE_MAX_PAGE
  },

  isTransactionsLoading: false,
  isChartLoading: false,
  additionalOptions: {
    net: null,
    address: null,
    period: DEFAULT_CHART_PERIOD
  }
})

const chartOptionsToDataMap = {
  chartType: {
    balance: 1,
    reward: 2
  },
  currency: {
    usd: 0,
    btc: 1
  }
}

export const getters = {
  [TRANSACTION.GETTER.GET_TRANSACTIONS_FILTER]: state => state.filter,
  [TRANSACTION.GETTER.GET_TRANSACTIONS_FOR_TABLE]: (state, getters) => {
    return state.transactions.map(
      ({ id, hash, net, from, to, date, value, type, direction, isCanceled, isReward, originalOpType }) => {
        const network = getters[NETWORK.GETTER.GET_NETWORK_BY_NET](net)
        return {
          id,
          key: hash + id,
          hash,
          hashUrl: getTransactionUrl(net, hash),
          walletAddress: from || to || '',
          datetime: dayjs(date).format('DD.MM.YYYY'),
          token: network.code,
          netCode: network.code,
          quantity: numberFormatterByCurrency(value),
          btc: numberFormatterByCurrency(value * network.rates.BTC, 'btc'),
          dollar: numberFormatterByCurrency(value * network.rates.USD, 'usd'),
          status: { type, direction, isCanceled, isReward },
          originalOpType
        }
      }
    )
  },
  [TRANSACTION.GETTER.GET_TRANSACTIONS_FOR_WALLET_TABLE]: (state, getters) => {
    return state.transactions.map(
      ({
        id,
        hash,
        from,
        to,
        value,
        date,
        fee,
        comment,
        net,
        type,
        direction,
        isCanceled,
        isReward,
        originalOpType,
        note,
        price
      }) => {
        const network = getters[NETWORK.GETTER.GET_NETWORK_BY_NET](net)
        const currentToken = getters[ERC20.GETTER.GET_SELECTED_TOKEN]
        const currentBep20Token = getters[BEP20.GETTER.GET_SELECTED_TOKEN]
        const currentSnip20Token = getters[SNIP20.GETTER.GET_SELECTED_TOKEN]
        // numberFormatterByCurrency
        const format = d3Format.format('.15f')
        let val = value + ''
        if (val.includes('e')) {
          val = format(value)
        } else {
          val = value
        }
        const tmpVal = val.toString().split('.')
        const parseTo8Digits = val => {
          if (!val) return val
          let str = val + ''
          if (str.length > 15) {
            str = str.slice(0, 15).replace(/0*$/, '')
          }
          return str
        }
        if (tmpVal[1]) {
          tmpVal[1] = parseTo8Digits(tmpVal[1])
        }
        const tmpBtc = format(val * ((price && (price.btc || price.BTC)) || (network && network.rates.BTC) || 0))
          .toString()
          .split('.')
        const tmpDollar = format(val * ((price && (price.usd || price.USD)) || (network && network.rates.USD) || 0))
          .toString()
          .split('.')
        return {
          id,
          key: hash + id,
          from,
          to,
          hash,
          net,
          type,
          direction,
          isCanceled,
          isReward,
          fee,
          comment,
          note,
          valueInteger: tmpVal[0],
          valueFractional: tmpVal[1],
          btcInteger: tmpBtc[0],
          btcFractional: tmpBtc[1],
          dollarInteger: tmpDollar[0],
          dollarFractional: tmpDollar[1],
          netCode:
            (network && network.code) ||
            (currentToken && currentToken.code) ||
            (currentBep20Token && currentBep20Token.code) ||
            (currentSnip20Token && currentSnip20Token.name),
          hashUrl: getTransactionUrl(
            (network && network.net) ||
              (currentToken && currentToken.net) ||
              (currentBep20Token && currentBep20Token.net),
            hash
          ),
          date: date ? dayjs(date).format('MMM D, YYYY,') : null,
          time: date ? dayjs(date).format('HH:mm') : null,
          status: { type, direction, isCanceled, isReward, originalOpType },
          originalOpType
        }
      }
    )
  },
  [TRANSACTION.GETTER.GET_CHART_OPTIONS]: state => state.chartOptions,
  [TRANSACTION.GETTER.GET_TABLE_OPTIONS]: state => state.tableOptions,
  [TRANSACTION.GETTER.GET_CHART_DATA]: state => {
    const { chartType, currency } = state.chartOptions
    const chartData = state.chartData.map(chartPoint => {
      return [
        chartPoint[0],
        chartPoint[chartOptionsToDataMap.chartType[chartType]]
          ? chartPoint[chartOptionsToDataMap.chartType[chartType]][chartOptionsToDataMap.currency[currency]]
          : 0
      ]
    })

    return chartData
  },
  [TRANSACTION.GETTER.IS_TRANSACTIONS_LOADING]: state => state.isTransactionsLoading,
  [TRANSACTION.GETTER.IS_CHART_LOADING]: state => state.isChartLoading,
  [TRANSACTION.GETTER.GET_TRANSACTIONS_QUANTITY]: state => state.transactionsQuantity
}

export const mutations = {
  [TRANSACTION.MUTATION.SET_TRANSACTIONS_FILTER]: (state, value) => {
    state.filter = value
  },
  [TRANSACTION.MUTATION.SET_ADDITIONAL_OPTIONS]: (state, options) => {
    state.additionalOptions = options

    // initial transactions from cache
    if (options.net && options.address) {
      const oldTransactionsList = localStorage.getItem(`${options.net.toLowerCase()}${options.address}`)

      if (oldTransactionsList) {
        state.transactions = JSON.parse(oldTransactionsList)
      }
    }
  },
  [TRANSACTION.MUTATION.SET_TRANSACTIONS]: (state, transactionsResponse) => {
    state.transactionsQuantity = transactionsResponse.count ? transactionsResponse.count : state.transactionsQuantity
    state.transactions = transactionsResponse.list
    state.tableOptions.maxPage = transactionsResponse.count
      ? Math.ceil(transactionsResponse.count / state.tableOptions.limit)
      : state.tableOptions.maxPage
    // cache transactions
    if (transactionsResponse.list && transactionsResponse.list.length) {
      if (state.additionalOptions.net) {
        localStorage.setItem(
          `${state.additionalOptions.net.toLowerCase()}${state.additionalOptions.address}`,
          JSON.stringify(transactionsResponse.list)
        )
      }
    }
  },
  [TRANSACTION.MUTATION.SET_CHART_DATA]: (state, chartData) => {
    state.chartData = chartData
  },

  /* CHART_OPTIONS */
  [TRANSACTION.MUTATION.SET_CHART_CURRENCY]: (state, currency) => {
    if (chartOptionsToDataMap.currency[currency] === undefined) {
      chartOptionsToDataMap.currency[currency] = CURRENT_CURRENCY_FOR_GRAPH
    }
    state.chartOptions.currency = currency
  },
  [TRANSACTION.MUTATION.SET_CHART_PERIOD]: (state, { period, page }) => {
    state.chartOptions.period = period
    if (page) state.chartOptions.customPeriod = { ...state.chartOptions.customPeriod, [page]: period }
  },
  [TRANSACTION.MUTATION.SET_CHART_TYPE]: (state, chartType) => {
    state.chartOptions.chartType = chartType
  },
  /* TABLE_OPTIONS */
  [TRANSACTION.MUTATION.SET_TABLE_PAGE]: (state, page) => {
    state.tableOptions.page = page
  },
  [TRANSACTION.MUTATION.SET_TABLE_LIMIT]: (state, limit) => {
    state.tableOptions.limit = limit || DEFAULT_TABLE_LIMIT
    state.tableOptions.page = DEFAULT_TABLE_PAGE_NUMBER
  },
  /* TABLE_OPTIONS */

  [TRANSACTION.MUTATION.SET_IS_TRANSACTIONS_LOADING]: (state, value) => {
    state.isTransactionsLoading = value
  },
  [TRANSACTION.MUTATION.SET_IS_CHART_LOADING]: (state, value) => {
    state.isChartLoading = value
  }
}

let reqCount = 0

export const actions = {
  [TRANSACTION.ACTION.LOAD_CHART_AND_TRANSACTIONS]({ commit, state, getters }, page) {
    try {
      commit(TRANSACTION.MUTATION.SET_IS_CHART_LOADING, true)
      commit(TRANSACTION.MUTATION.SET_IS_TRANSACTIONS_LOADING, true)

      commit(TRANSACTION.MUTATION.SET_TRANSACTIONS, { list: [], count: 0 })
      commit(TRANSACTION.MUTATION.SET_TABLE_PAGE, DEFAULT_TABLE_PAGE_NUMBER)
      commit(TRANSACTION.MUTATION.SET_TABLE_LIMIT, DEFAULT_TABLE_LIMIT)
      commit(TRANSACTION.MUTATION.SET_CHART_DATA, [])

      const transactionTableOptions = getters[TRANSACTION.GETTER.GET_TABLE_OPTIONS]

      reqCount += 1
      const prevReqCount = reqCount

      const pendingTransactions = state.additionalOptions.net
        ? this.$api
            .getTransactionList({
              ...state.additionalOptions,
              params: {
                offset: transactionTableOptions.limit * (transactionTableOptions.page - 1),
                limit: transactionTableOptions.limit,
                type: state.filter ? state.filter : null
              }
            })
            .then(resp => {
              if (prevReqCount === reqCount) {
                commit(TRANSACTION.MUTATION.SET_TRANSACTIONS, resp.data)
                commit(NETWORK.MUTATION.SET_NETWORKS, resp.data.currency)
                commit(TRANSACTION.MUTATION.SET_IS_TRANSACTIONS_LOADING, false)
              }
            })
        : null

      /**
       * сохраненняем данные по глубине графика, если их нет, то undefined
       * и на сервер летит запрос без параметра ?period=...
       */
      state.additionalOptions.period = state.chartOptions.customPeriod[page]

      const pendingChartData = this.$api.getChartData(state.additionalOptions).then(({ data }) => {
        let period = ''
        /**
         * Новый ответ сервера будет содержать массив graph с данными для графика
         * и глубину отображения данных - period
         */
        if (Array.isArray(data.graph)) {
          period = data.period
          data = data.graph
        }
        if (prevReqCount === reqCount) {
          commit(TRANSACTION.MUTATION.SET_CHART_DATA, data)

          // Если страница открывалась впервые сохраняем дефолтное значение глубины графика, полученное с сервера
          if (!state.additionalOptions.period) {
            commit(TRANSACTION.MUTATION.SET_CHART_PERIOD, { period, page })
          }

          commit(TRANSACTION.MUTATION.SET_IS_CHART_LOADING, false)
        }
      })

      Promise.all([pendingTransactions, pendingChartData]).then(() => {
        if (prevReqCount === reqCount) {
          reqCount = 0
        }
      })
    } catch (e) {
      console.error(e)
      commit(TRANSACTION.MUTATION.SET_IS_TRANSACTIONS_LOADING, false)
      commit(TRANSACTION.MUTATION.SET_IS_CHART_LOADING, false)
    }
  },
  [TRANSACTION.ACTION.LOAD_CHART]({ commit, state }, page) {
    try {
      commit(TRANSACTION.MUTATION.SET_IS_CHART_LOADING, true)
      commit(TRANSACTION.MUTATION.SET_CHART_DATA, [])

      reqCount += 1
      const prevReqCount = reqCount

      /**
       * сохраненняем данные по глубине графика, если их нет, то undefined
       * и на сервер летит запрос без параметра ?period=...
       */
      state.additionalOptions.period = state.chartOptions.customPeriod[page]

      const pendingChartData = this.$api.getChartData(state.additionalOptions).then(({ data }) => {
        let period = ''
        /**
         * Новый ответ сервера будет содержать массив graph с данными для графика
         * и глубину отображения данных - period
         */
        if (Array.isArray(data.graph)) {
          period = data.period
          data = data.graph
        }
        if (prevReqCount === reqCount) {
          commit(TRANSACTION.MUTATION.SET_CHART_DATA, data)

          // Если страница открывалась впервые сохраняем дефолтное значение глубины графика, полученное с сервера
          if (!state.additionalOptions.period) {
            commit(TRANSACTION.MUTATION.SET_CHART_PERIOD, { period, page })
          }
          commit(TRANSACTION.MUTATION.SET_IS_CHART_LOADING, false)
        }
      })

      pendingChartData.then(() => {
        if (prevReqCount === reqCount) {
          reqCount = 0
        }
      })
    } catch (e) {
      console.error(e)
      commit(TRANSACTION.MUTATION.SET_IS_CHART_LOADING, false)
    }
  },
  async [TRANSACTION.ACTION.LOAD_TRANSACTIONS_PAGE]({ commit, getters, state, dispatch }) {
    try {
      const oldTransactionsList = localStorage.getItem(
        `${state.additionalOptions.net}${state.additionalOptions.address}`
      )

      // if receive transactions from cache - loader not show
      if (!oldTransactionsList) {
        commit(TRANSACTION.MUTATION.SET_IS_TRANSACTIONS_LOADING, true)
      } else {
        // commit(TRANSACTION.MUTATION.SET_TRANSACTIONS, { list: JSON.parse(oldTransactionsList) })
      }

      const transactionTableOptions = getters[TRANSACTION.GETTER.GET_TABLE_OPTIONS]
      const data = {
        ...state.additionalOptions,
        params: {
          offset: transactionTableOptions.limit * (transactionTableOptions.page - 1),
          limit: transactionTableOptions.limit,
          type: state.filter ? state.filter : null
        }
      }

      const snip20Token = getters[SNIP20.GETTER.GET_SELECTED_TOKEN]
      if (snip20Token && snip20Token.net !== 'secret') {
        const txResult = await dispatch(SNIP20.ACTION.LOAD_TOKEN_TRANSACTIONS, {
          walletAddress: state.additionalOptions.address,
          contractAddress: snip20Token.address,
          page: transactionTableOptions.page - 1
        })
        const txs = (txResult.isError && snip20Token.txs) || (txResult.value && txResult.value.txs) || []
        const snip20TotalTxs =
          (txResult.isError && snip20Token.totalTxs) || (txResult.value && txResult.value.totalTxs) || null

        const list = txs
          .map(tx => {
            return {
              from: tx.sender,
              to: tx.receiver,
              value: snip20Token ? Number(tx.coins.amount) / 10 ** snip20Token.decimals : tx.coins.amount,
              id: tx.id,
              direction:
                state.additionalOptions.address === tx.sender
                  ? 'outcome'
                  : state.additionalOptions.address === tx.receiver
                  ? 'income'
                  : 'transfer',
              type: 'transfer',
              net: snip20Token.net,
              price: getters[netCurrencyTypes.GET_CURRENCY_BY_NET](snip20Token.net)
            }
          })
          .filter(c => (state.filter ? c.direction === state.filter : true))
        const count =
          snip20TotalTxs ||
          (txs.length !== 0 ? (transactionTableOptions.page + 1) * 5 : transactionTableOptions.page * 5)
        commit(TRANSACTION.MUTATION.SET_TRANSACTIONS, { list, count } || { list: [] })
        return
      }

      if (state.additionalOptions.net && !(snip20Token && snip20Token.net !== 'secret')) {
        const response = await this.$api.getTransactionList(data)
        const additionalOptions = state.additionalOptions

        if (data.net === additionalOptions.net && data.address === additionalOptions.address) {
          commit(TRANSACTION.MUTATION.SET_TRANSACTIONS, response.data)
          if (response.data.currency) {
            commit(NETWORK.MUTATION.SET_NETWORKS, response.data.currency)
          }
        }
      }
    } catch (e) {
      commit(TRANSACTION.MUTATION.SET_TRANSACTIONS, { list: [] })
    } finally {
      commit(TRANSACTION.MUTATION.SET_IS_TRANSACTIONS_LOADING, false)
    }
  }
}
