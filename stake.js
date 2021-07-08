async [STAKE_COIN_OPERATION.ACTION.TRY_STAKE]({ getters, state, commit, dispatch }) {
    commit('setSuccessStake', null)
    try {
      commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, null)
      commit(STAKE_COIN_OPERATION.MUTATION.SET_TX_HASH, null)
      commit(STAKE_COIN_OPERATION.MUTATION.SET_PASSWORD_ERROR, false)
      commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, '')
      commit(STAKE_COIN_OPERATION.MUTATION.SET_IS_DELEGATING, true)

      const coin = getters[INTERNAL_WALLET.GETTER.GET_SELECTED_COIN]
      const selectedOptions = getters[INTERNAL_WALLET.GETTER.GET_CURRENT_WALLET_AND_COIN]
      const { password } = getters[STAKE_COIN_OPERATION.GETTER.GET_DATA]
      const rawTXs = getters[STAKE_COIN_OPERATION.GETTER.GET_RAW_TRANSACTIONS]
      const delegationBalance = getters[INTERNAL_WALLET.GETTER.GET_DELEGATION_BALANCE_INFO](coin.id)
      const token = getters[ERC20.GETTER.GET_SELECTED_TOKEN]
      const net = getCurrentNet(coin.network || coin.net, token)

      let gasDiff = -1
      let iostAmountForBuy = 0

const hash = await this.$controllers.wallets.signAndSendTransaction({
          type: 'delegate',
          data: rawTx,
          walletId: selectedOptions.walletId,
          gasDiff: state.ramBuyConfirm ? 0 : iostAmountForBuy,
          ramBuyConfirm: state.ramBuyConfirm ? state.ramDiff : 0,
          address: coin.address,
          password,
          network: coin.network
        })
        iostAmountForBuy = 0
        if (hash === 'passwordError') {
          commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, 'Incorrect password')
          commit(STAKE_COIN_OPERATION.MUTATION.SET_PASSWORD_ERROR, true)
          return false
        }

        if (hash && isErrorResponse(hash)) {
          const dataError = hash.split(',')
          if (dataError.length === 3) {
            commit('setRamDiff', dataError[1])
            commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, null)
            commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, { title: 'Gas availability', state: 'finish' })
            commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, { title: 'Ram availability', state: 'cancel' })
            return false
          }
          commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, hash)
          commit(STAKE_COIN_OPERATION.MUTATION.SET_PASSWORD_ERROR, true)

          commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, null)
          commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, { title: 'Gas availability', state: 'cancel' })
          commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, { title: 'Ram availability', state: 'finish' })
          commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, { title: 'IOST availability', state: 'cancel' })
          commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, { title: 'Failed', state: 'cancel' })
          return false
        }

        if (hash === 'buy ram' || hash === 'buy gas') {
          if (hash === 'buy gas') {
            commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, null)
            commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, { title: 'Gas availability', state: 'finish' })
            commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, { title: 'Gas enough', state: 'process' })
            await dispatch(INTERNAL_WALLET.ACTION.LOAD_DELEGATION_BALANCE_INFO)
            commit(STAKE_COIN_OPERATION.MUTATION.SET_STAKE_MODAL_OPEN, false)
            commit(STAKE_COIN_OPERATION.MUTATION.SET_CONFIRM_STAKE_MODAL_OPEN, false)
            commit(STAKE_COIN_OPERATION.MUTATION.SET_SELECTED_NODE, null)
            commit(STAKE_COIN_OPERATION.MUTATION.SET_TX_HASH, null)
            commit('setGasDiff', 0)
            commit('setGasBuyConfirm', null)
            commit(STAKE_COIN_OPERATION.MUTATION.SET_DATA_EMPTY)
            commit('setUpdateGasRamFlag', true)
            return
          }

          if (Array.isArray(hash)) {
            commit(STAKE_COIN_OPERATION.MUTATION.SET_TX_HASH, hash[0])
          }
          if (typeof hash === 'string') {
            commit(STAKE_COIN_OPERATION.MUTATION.SET_TX_HASH, hash)
          }

          commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, null)
          commit('setSuccessStake', true)
          commit('setGasDiff', 0)
          commit('setGasBuyConfirm', null)
          commit('setRamDiff', 0)
          commit('setRamBuyConfirm', null)
          commit('setUpdateGasRamFlag', true)
          dispatch(INTERNAL_WALLET.ACTION.LOAD_DELEGATION_BALANCE_INFO)
        }
      }
      commit(STAKE_COIN_OPERATION.MUTATION.SET_STAKE_MODAL_OPEN, false)
      commit(STAKE_COIN_OPERATION.MUTATION.SET_CONFIRM_STAKE_MODAL_OPEN, false)
      commit(STAKE_COIN_OPERATION.MUTATION.SET_SELECTED_NODE, null)
      await dispatch(STAKE_COIN_OPERATION.ACTION.LOAD_STACKING_TRANSACTIONS)
    } catch (error) {
      commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, null)
      commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, { title: 'IOST availability', state: 'cancel' })
      commit(STAKE_COIN_OPERATION.MUTATION.SET_IOST_STAKE_FLOW, { title: 'Failed', state: 'cancel' })
      if (error instanceof PasswordInvalidError) {
        commit(STAKE_COIN_OPERATION.MUTATION.SET_DATA_FIELD, {
          field: 'isPasswordInvalid',
          value: true
        })
        return
      }
      console.error(error)
      Sentry.captureMessage('Error in STAKE_COIN_OPERATION.ACTION.TRY_STAKE function' + error.data || error.message)
      Sentry.captureException(error)
      if (error.data || error.message) {
        commit(STAKE_COIN_OPERATION.MUTATION.SET_PASSWORD_ERROR, true)
        if (error.data) {
          commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, error.data.error)
        } else {
          commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, error.message)
        }
      }
    } finally {
      commit(STAKE_COIN_OPERATION.MUTATION.SET_IS_DELEGATING, false)
    }
  }
