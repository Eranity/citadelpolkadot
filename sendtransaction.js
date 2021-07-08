import { getCoinClassByNetwork } from '@@/lib/citadel/wallet/coins'
import { PasswordInvalidError } from '@@/lib/citadel/wallet/exceptions/password-invalid.error'
import { WalletTypes } from '@@/lib/citadel/wallet'
import * as Sentry from '@sentry/vue'
import { decodeBufferByPassword } from '@@/lib/citadel/crypto'
import netCurrencyTypes from './storeTypes/netCurrencyTypes'
import userWalletTypes from './storeTypes/userWalletTypes'
import { getTransactionUrl } from '@/helpers/transactions-helpers'
import {
  SEND_COIN_OPERATION,
  STAKE_COIN_OPERATION,
  INTERNAL_WALLET,
  NETWORK,
  ERC20,
  SNIP20,
  PROFILE,
  BRIDGE,
  NETWORKS_CONFIG,
  BEP20
} from '@/store/types'
import { getCurrentEncodedPrivateKey, getMainNet } from '~/helpers'

export const namespaced = false

export const state = () => ({
  data: {
    sendTo: '',
    amount: 0,
    btc: 0,
    usd: 0,
    memo: '',
    fee: 0,
    secondaryFee: '',
    gasPrice: 0
  },
  confirmData: {
    password: '',
    rawUnsignedTransaction: null,
    isPasswordInvalid: false
  },
  isTransferring: false,
  isPreparing: false,
  isConfirmDialogOpen: false,
  txHash: null,
  error: null,
  isOpen: false,
  isOpen2: false
})

export const getters = {
  [SEND_COIN_OPERATION.GETTER.GET_DATA]: state => state.data,
  [SEND_COIN_OPERATION.GETTER.IS_CLAIM_MODAL_OPEN]: state => state.isOpen,
  [SEND_COIN_OPERATION.GETTER.IS_SEND_MODAL_OPEN]: state => state.isOpen2,
  [SEND_COIN_OPERATION.GETTER.GET_CALCULATED_RATES]: state => {
    // const coin = getters[INTERNAL_WALLET.GETTER.GET_SELECTED_COIN]
    // const rate = (coin && coin.rate) || { usd: 0, btc: 0 }

    return {
      amount: state.data.amount,
      usd: state.data.usd,
      btc: state.data.btc
    }
  },
  [SEND_COIN_OPERATION.GETTER.GET_CONFIRM_DATA]: state => state.confirmData,
  [SEND_COIN_OPERATION.GETTER.PARSED_RAW_TRANSACTION]: (state, getters) => {
    const coin = getters[INTERNAL_WALLET.GETTER.GET_SELECTED_COIN]
    const parsedData =
      (coin &&
        state.confirmData.rawUnsignedTransaction &&
        getCoinClassByNetwork(coin.network, WalletTypes.ONE_SEED).getDataFromRawTransaction(
          state.confirmData.rawUnsignedTransaction
        )) ||
      {}

    return {
      to: state.confirmData.sendTo || parsedData.to || state.data.sendTo,
      from: coin.address || parsedData.from || state.data.sendTo,
      fee: state.data.fee,
      secondaryFee: state.data.secondaryFee,
      amount: state.data.amount || parsedData.amount,
      memo:
        state.data.memo ||
        parsedData.memo ||
        (state.confirmData &&
          state.confirmData.rawUnsignedTransaction &&
          state.confirmData.rawUnsignedTransaction.json &&
          state.confirmData.rawUnsignedTransaction.json.memo)
    }
  },
  [SEND_COIN_OPERATION.GETTER.IS_CONFIRM_DIALOG_OPEN]: state => state.isConfirmDialogOpen,
  [SEND_COIN_OPERATION.GETTER.IS_LOADING]: state => state.isTransferring || state.isPreparing,
  [SEND_COIN_OPERATION.GETTER.GET_TX_HASH]: (state, getters) => {
    const coin = getters[INTERNAL_WALLET.GETTER.GET_SELECTED_COIN]

    if (Array.isArray(state.txHash)) {
      return state.txHash.map(hash => ({
        url: getTransactionUrl(coin.network, hash),
        hash
      }))
    } else if (typeof state.txHash === 'string') {
      return {
        url: getTransactionUrl(coin.network, state.txHash),
        hash: state.txHash
      }
    }
    return null
  },
  [SEND_COIN_OPERATION.GETTER.GET_ERROR]: state => state.error,
  [SEND_COIN_OPERATION.GETTER.IS_PASSWORD_INVALID]: state => state.confirmData.isPasswordInvalid
}

export const mutations = {
  [SEND_COIN_OPERATION.MUTATION.SET_CLAIM_MODAL_OPEN]: (state, value) => {
    state.isOpen = value
  },
  [SEND_COIN_OPERATION.MUTATION.SET_SEND_MODAL_OPEN]: (state, value) => {
    state.isOpen2 = value
  },
  [SEND_COIN_OPERATION.MUTATION.SET_DATA_EMPTY]: state => {
    for (const key in state.data) {
      state.data[key] = ''
    }
    state.confirmData.rawUnsignedTransaction = {}
    state.confirmData.password = ''
    state.confirmData.isPasswordInvalid = false
    state.txHash = null
  },
  [SEND_COIN_OPERATION.MUTATION.SET_DATA_FIELD]: (state, payload) => {
    state.data[payload.field] = payload.value
  },
  [SEND_COIN_OPERATION.MUTATION.SET_IS_PREPARING]: (state, value) => {
    state.isPreparing = value
  },
  [SEND_COIN_OPERATION.MUTATION.SET_IS_TRANSFERRING]: (state, value) => {
    state.isTransferring = value
  },
  [SEND_COIN_OPERATION.MUTATION.SET_RAW_TRANSACTION]: (state, value) => {
    state.confirmData.rawUnsignedTransaction = value
  },
  [SEND_COIN_OPERATION.MUTATION.SET_CONFIRM_PASSWORD]: (state, value) => {
    state.confirmData.password = value
  },
  [SEND_COIN_OPERATION.MUTATION.SET_IS_PASSWORD_INVALID]: (state, value) => {
    state.confirmData.isPasswordInvalid = value
  },
  [SEND_COIN_OPERATION.MUTATION.SET_CONFIRM_DIALOG_OPEN]: (state, value) => {
    state.isConfirmDialogOpen = value
  },
  [SEND_COIN_OPERATION.MUTATION.SET_TX_HASH]: (state, value) => {
    state.txHash = value
  },
  [SEND_COIN_OPERATION.MUTATION.SET_ERROR]: (state, message) => {
    state.error = message
  }
}

export const actions = {
  [SEND_COIN_OPERATION.ACTION.SET_AND_CALCULATE_AMOUNT]({ getters, commit }, { amount, btc, usd, coinParam }) {
    const { USD } = getters[NETWORK.GETTER.GET_NETWORK_BY_CODE]('BTC').rates

    let coinKey
    coinKey = coinParam
    if (coinParam === 'ETH_USDT') coinKey = 'USDT'
    if (coinParam === 'Tezos') coinKey = 'XTZ'
    if (coinParam === 'ICON') coinKey = 'ICX'
    if (coinParam === 'Cosmos') coinKey = 'COSMOS'
    if (coinParam === 'Band') coinKey = 'BAND'
    if (coinParam === 'Kava') coinKey = 'KAVA'
    if (coinParam === 'Secret') coinKey = 'SCRT'
    if (coinParam === 'Polkadot') coinKey = 'DOT'
    const coinData = getters[NETWORK.GETTER.GET_NETWORK_BY_CODE](coinKey)
    let rates = (coinData && coinData.rates) || { USD: 0, BTC: 0 }

    const token = getters[ERC20.GETTER.GET_SELECTED_TOKEN] || getters[BEP20.GETTER.GET_SELECTED_TOKEN]
    if (token) rates = token.price

    const snip20Token = getters[SNIP20.GETTER.GET_SELECTED_TOKEN]
    if (snip20Token && snip20Token.net !== 'secret')
      rates = getters[netCurrencyTypes.GET_CURRENCY_BY_NET](snip20Token.net)

    if (!rates) rates = { BTC: 0, USD: 0 }

    if (typeof amount === 'number') {
      commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_FIELD, { field: 'amount', value: amount })
      commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_FIELD, { field: 'btc', value: amount * rates.BTC })
      commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_FIELD, { field: 'usd', value: amount * rates.USD })
    }
    if (typeof btc === 'number') {
      commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_FIELD, { field: 'btc', value: btc })
      commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_FIELD, { field: 'amount', value: (btc / rates.BTC).toFixed(8) })
      commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_FIELD, {
        field: 'usd',
        value: +USD * btc
      })
    }
    if (typeof usd === 'number') {
      commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_FIELD, { field: 'usd', value: usd })
      commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_FIELD, { field: 'amount', value: (usd / rates.USD).toFixed(8) })
      commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_FIELD, {
        field: 'btc',
        value: (1 / USD) * usd
      })
    }
    if (usd === 0 || btc === 0) {
      commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_FIELD, { field: 'usd', value: 0 })
      commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_FIELD, { field: 'amount', value: 0 })
      commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_FIELD, {
        field: 'btc',
        value: 0
      })
    }
  },
  async [SEND_COIN_OPERATION.ACTION.PREPARE_TRANSFER]({ commit, getters }) {
    commit(SEND_COIN_OPERATION.MUTATION.SET_TX_HASH, null)
    commit(SEND_COIN_OPERATION.MUTATION.SET_ERROR, '')
    commit(STAKE_COIN_OPERATION.MUTATION.SET_TX_HASH, null)
    commit(STAKE_COIN_OPERATION.MUTATION.SET_PASSWORD_ERROR, false)
    commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, '')

    try {
      commit(SEND_COIN_OPERATION.MUTATION.SET_IS_PREPARING, true)

      const { sendTo, sendFrom, amount, memo, fee, gasPrice } = getters[SEND_COIN_OPERATION.GETTER.GET_DATA]
      const coin = getters[INTERNAL_WALLET.GETTER.GET_SELECTED_COIN]
      const erc20Token = getters[ERC20.GETTER.GET_SELECTED_TOKEN]
      const bep20Token = getters[BEP20.GETTER.GET_SELECTED_TOKEN]
      const network = (erc20Token && erc20Token.net) || (bep20Token && bep20Token.net) || coin.network
      const snip20Token = getters[SNIP20.GETTER.GET_SELECTED_TOKEN]

      if (!(snip20Token && snip20Token.net !== 'secret')) {
        const transferRawData = await this.$api.prepareTransfer({
          from: coin.address,
          to: sendTo,
          network,
          amount,
          fee,
          gasPrice,
          publicKey: coin.publicKey,
          ...(sendFrom && sendFrom.includes('KT') && { kt: sendFrom, fee }),
          ...(memo && { memo })
        })

        commit(SEND_COIN_OPERATION.MUTATION.SET_RAW_TRANSACTION, transferRawData.data)
      }

      commit(SEND_COIN_OPERATION.MUTATION.SET_CONFIRM_DIALOG_OPEN, true)
    } catch (error) {
      commit(SEND_COIN_OPERATION.MUTATION.SET_ERROR, error.data.error)
      Sentry.captureMessage('Error in SEND_COIN_OPERATION.ACTION.PREPARE_TRANSFER:' + error)
      Sentry.captureException(error)
      return { error }
    } finally {
      commit(SEND_COIN_OPERATION.MUTATION.SET_IS_PREPARING, false)
    }
  },
  async [SEND_COIN_OPERATION.ACTION.CONFIRM_OPERATION]({ commit, getters }, params) {
    let returnHash = null
    commit(STAKE_COIN_OPERATION.MUTATION.SET_TX_HASH, null)
    commit(STAKE_COIN_OPERATION.MUTATION.SET_PASSWORD_ERROR, false)
    commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, '')
    try {
      commit(SEND_COIN_OPERATION.MUTATION.SET_IS_TRANSFERRING, true)

      const { rawUnsignedTransaction, password } = getters[SEND_COIN_OPERATION.GETTER.GET_CONFIRM_DATA]
      const coin = getters[INTERNAL_WALLET.GETTER.GET_SELECTED_COIN]
      const selectedOptions = getters[INTERNAL_WALLET.GETTER.GET_CURRENT_WALLET_AND_COIN]

      const hash = await this.$controllers.wallets.signAndSendTransaction({
        type: 'transfer',
        walletId: selectedOptions.walletId,
        address: coin.address,
        network: coin.network,
        data: JSON.parse(JSON.stringify(rawUnsignedTransaction)),
        password
      })
      if (hash === 'passwordError') {
        commit(STAKE_COIN_OPERATION.MUTATION.SET_PASSWORD_ERROR, true)
        commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, 'Incorrect password')
        return false
      }
      returnHash = hash

      // IOST
      // HIDE MODAL, BUT HASH UNDEFINED
      // if (state.confirmData.rawUnsignedTransaction.actions[0].contract === 'token.iost') {
      // commit(SEND_COIN_OPERATION.MUTATION.SET_CONFIRM_DIALOG_OPEN, false)
      // }
      if (!params || !params.isApproveTx) {
        commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_EMPTY)
        commit(SEND_COIN_OPERATION.MUTATION.SET_TX_HASH, hash)
      }
      if (!hash && (!params || !params.isApproveTx)) {
        commit(SEND_COIN_OPERATION.MUTATION.SET_CONFIRM_DIALOG_OPEN, false)
      }
    } catch (error) {
      if (error instanceof PasswordInvalidError) {
        commit(SEND_COIN_OPERATION.MUTATION.SET_IS_PASSWORD_INVALID, true)
        return
      }

      commit(STAKE_COIN_OPERATION.MUTATION.SET_PASSWORD_ERROR, true)

      if (error.data) {
        commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, error.data.error)
      } else if (error.message) {
        commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, error.message)
      } else {
        commit(SEND_COIN_OPERATION.MUTATION.SET_ERROR, 'Something went wrong, try again later')
      }
      console.error(error)
      Sentry.captureMessage('Error in SEND_COIN_OPERATION.ACTION.CONFIRM_OPERATION: ' + error)
      Sentry.captureException(error)
      return { error }
    } finally {
      commit(SEND_COIN_OPERATION.MUTATION.SET_IS_TRANSFERRING, false)
    }
    return returnHash
  },
  async [SEND_COIN_OPERATION.ACTION.CONFIRM_SNIP20_TRANSFER]({ commit, getters, dispatch }) {
    commit(STAKE_COIN_OPERATION.MUTATION.SET_TX_HASH, null)
    commit(STAKE_COIN_OPERATION.MUTATION.SET_PASSWORD_ERROR, false)
    commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, '')

    try {
      commit(SEND_COIN_OPERATION.MUTATION.SET_IS_TRANSFERRING, true)

      const { password } = getters[SEND_COIN_OPERATION.GETTER.GET_CONFIRM_DATA]
      const coin = getters[INTERNAL_WALLET.GETTER.GET_SELECTED_COIN]
      const { type } = getters[userWalletTypes.GET_CURRENT_WALLET]
      const userId = getters[PROFILE.GETTER.USER_ID]
      const snip20Token = getters[SNIP20.GETTER.GET_SELECTED_TOKEN]
      const { sendTo, amount, fee } = getters[SEND_COIN_OPERATION.GETTER.GET_DATA]

      const encodedPrivateKey = getCurrentEncodedPrivateKey(coin.address, getters[PROFILE.GETTER.USER].id)
      const privateKey = decodeBufferByPassword(encodedPrivateKey, password)

      const result = await this.$snip20.transfer(
        coin.address,
        snip20Token.address,
        sendTo,
        privateKey,
        amount,
        fee,
        type,
        userId,
        snip20Token.decimals
      )
      if (!result.error && result.transferResult.transactionHash) {
        commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_EMPTY)
        commit(SEND_COIN_OPERATION.MUTATION.SET_TX_HASH, result.transferResult.transactionHash)
        await dispatch(SNIP20.ACTION.LOAD_TOKEN_BALANCE, {
          walletAddress: coin.address,
          contractAddress: snip20Token.address
        })
        dispatch(SNIP20.ACTION.LOAD_TOKEN_TRANSACTIONS, {
          walletAddress: coin.address,
          contractAddress: snip20Token.address
        })
      }
      if (result.error) {
        commit(SEND_COIN_OPERATION.MUTATION.SET_CONFIRM_DIALOG_OPEN, false)
        throw result
      }
    } catch (error) {
      if (error instanceof PasswordInvalidError) {
        commit(SEND_COIN_OPERATION.MUTATION.SET_IS_PASSWORD_INVALID, true)
        return
      }

      commit(STAKE_COIN_OPERATION.MUTATION.SET_PASSWORD_ERROR, true)

      if (error.data) {
        commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, error.data.error)
      } else if (error.message) {
        commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, error.message)
      } else {
        commit(SEND_COIN_OPERATION.MUTATION.SET_ERROR, 'Something went wrong, try again later')
      }
      console.error(error)
      Sentry.captureMessage('Error in SEND_COIN_OPERATION.ACTION.CONFIRM_SNIP20_OPERATION: ' + error)
      Sentry.captureException(error)
      return { error }
    } finally {
      commit(SEND_COIN_OPERATION.MUTATION.SET_IS_TRANSFERRING, false)
    }
  },
  async [SEND_COIN_OPERATION.ACTION.CONFIRM_BRIDGE_OPERATION]({ commit, dispatch, getters, state }) {
    commit(STAKE_COIN_OPERATION.MUTATION.SET_TX_HASH, null)
    commit(STAKE_COIN_OPERATION.MUTATION.SET_PASSWORD_ERROR, false)
    commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, '')
    try {
      commit(SEND_COIN_OPERATION.MUTATION.SET_IS_TRANSFERRING, true)

      const { password } = getters[SEND_COIN_OPERATION.GETTER.GET_CONFIRM_DATA]
      const coin = getters[INTERNAL_WALLET.GETTER.GET_SELECTED_COIN]
      const { type } = getters[userWalletTypes.GET_CURRENT_WALLET]
      const userId = getters[PROFILE.GETTER.USER_ID]
      const snip20Token = getters[SNIP20.GETTER.GET_SELECTED_TOKEN]
      const erc20token = getters[ERC20.GETTER.GET_SELECTED_TOKEN]
      const token = snip20Token || erc20token
      const { sendTo, amount, fee } = getters[SEND_COIN_OPERATION.GETTER.GET_DATA]

      const encodedPrivateKey = getCurrentEncodedPrivateKey(coin.address, getters[PROFILE.GETTER.USER].id)
      const privateKey = decodeBufferByPassword(encodedPrivateKey, password)
      const config = getters[NETWORKS_CONFIG.GETTER.GET_CONFIG]
      let bridgeContract = null
      if (token && token.net.includes('secret_') && token.net !== 'secret_scrt') {
        bridgeContract = (config && config.secret && config.secret.bridges && config.secret.bridges.eth) || null
      }

      const result = await getConvertFunc(token.net, this.$snip20)(
        {
          walletAddress: coin.address,
          contractAddress: (snip20Token && snip20Token.address) || null,
          toAddress: sendTo,
          privateKey,
          amount,
          fee,
          walletType: type,
          userId,
          decimals: (snip20Token && snip20Token.decimals) || null,
          bridgeContract,
          ethDisapproveTx: getters[BRIDGE.GETTER.GET_DISAPPROVE_TX],
          ethApproveTx: getters[BRIDGE.GETTER.GET_APPROVE_TX],
          ethTransferTx: state.confirmData.rawUnsignedTransaction
        },
        {
          getSignFunc: this.$snip20.getSignFunc,
          dispatch,
          commit,
          getters
        }
      )
      if (!result.error && result.convertResult.transactionHash) {
        commit(SEND_COIN_OPERATION.MUTATION.SET_DATA_EMPTY)
        commit(SEND_COIN_OPERATION.MUTATION.SET_TX_HASH, result.convertResult.transactionHash)
        if (token.net.includes('secret_') && token.address) {
          await dispatch(SNIP20.ACTION.LOAD_TOKEN_BALANCE, {
            walletAddress: coin.address,
            contractAddress: token.address
          })
          await dispatch(SNIP20.ACTION.LOAD_TOKEN_TRANSACTIONS, {
            walletAddress: coin.address,
            contractAddress: token.address
          })
        }
      }
      if (result.error) {
        commit(SEND_COIN_OPERATION.MUTATION.SET_CONFIRM_DIALOG_OPEN, false)
        throw result
      }
    } catch (error) {
      if (error instanceof PasswordInvalidError) {
        commit(SEND_COIN_OPERATION.MUTATION.SET_IS_PASSWORD_INVALID, true)
        return
      }

      commit(STAKE_COIN_OPERATION.MUTATION.SET_PASSWORD_ERROR, true)

      commit(BRIDGE.MUTATION.SET_ERROR, (error && error.err) || error)
      console.error(error)
      Sentry.captureMessage('Error in SEND_COIN_OPERATION.ACTION.CONFIRM_BRIDGE_OPERATION: ' + error)
      Sentry.captureException(error)
      return { error }
    } finally {
      commit(SEND_COIN_OPERATION.MUTATION.SET_IS_TRANSFERRING, false)
      commit(BRIDGE.MUTATION.SET_IS_BRIDGE_OPERATION, false)
    }
  }
}

const convertEth = async (_, { dispatch }) => {
  const hash = await dispatch(SEND_COIN_OPERATION.ACTION.CONFIRM_OPERATION)
  return { error: false, convertResult: { transactionHash: hash } }
}
const convertEthToken = async ({ ethDisapproveTx, ethApproveTx, ethTransferTx }, { dispatch, commit }) => {
  if (ethDisapproveTx) {
    commit(SEND_COIN_OPERATION.MUTATION.SET_RAW_TRANSACTION, ethDisapproveTx)
    await dispatch(SEND_COIN_OPERATION.ACTION.CONFIRM_OPERATION, { isApproveTx: true })
  }

  // approve tx
  if (ethApproveTx) {
    commit(SEND_COIN_OPERATION.MUTATION.SET_RAW_TRANSACTION, ethApproveTx)
    await dispatch(SEND_COIN_OPERATION.ACTION.CONFIRM_OPERATION, { isApproveTx: true })
  }

  // convert tx
  commit(SEND_COIN_OPERATION.MUTATION.SET_RAW_TRANSACTION, ethTransferTx)
  const hash = await dispatch(SEND_COIN_OPERATION.ACTION.CONFIRM_OPERATION)
  return { error: false, convertResult: { transactionHash: hash } }
}

const getConvertFunc = (sourceNet, $snip20) => {
  const mapNetToFunc = {
    secret_: $snip20.convertScrtToEth,
    secret: $snip20.convertScrtToSecretScrt,
    secret_scrt: $snip20.convertSecretScrtToScrt,
    eth: convertEth,
    eth_: convertEthToken
  }
  let net = sourceNet
  if (getMainNet(sourceNet) === 'secret') {
    net = sourceNet !== 'secret' && sourceNet !== 'secret_scrt' ? 'secret_' : sourceNet
  }
  if (getMainNet(sourceNet) === 'eth') {
    net = net.includes('eth_') ? 'eth_' : sourceNet
  }

  return mapNetToFunc[net]
}
