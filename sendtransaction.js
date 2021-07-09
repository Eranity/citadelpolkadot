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
  }
