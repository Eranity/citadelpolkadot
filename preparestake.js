async [STAKE_COIN_OPERATION.ACTION.PREPARE_DELEGATION]({ state, getters, commit }, opts) {
    commit(STAKE_COIN_OPERATION.MUTATION.SET_RAW_TRANSACTIONS, [])
    commit(STAKE_COIN_OPERATION.MUTATION.SET_SINGLE_REMOVE_NODE_MODE, false)
    try {
      commit(STAKE_COIN_OPERATION.MUTATION.SET_IS_PREPARING_STAKE, true)

      const coin = getters[INTERNAL_WALLET.GETTER.GET_SELECTED_COIN]
      const net = getCurrentNet(coin.network, getters[ERC20.GETTER.GET_SELECTED_TOKEN])

      const delegationBalanceInfo = getters[INTERNAL_WALLET.GETTER.GET_DELEGATION_BALANCE_INFO](coin.id)
      let stakeNodes = getters[STAKE_COIN_OPERATION.GETTER.GET_STAKE_NODES].filter(node => {
        // old list to icon send
        if(net === 'eth_orbs') return true
        if (net === 'icon' && node.isStaked) return true
        if (!node.isStaked) return true
        if (node.amount !== state.transactions.find(tr => tr.current === node.address).value) {
          return true
        }
        return false
      })
      // when triggered from /send page (autostake)
      let autoDelegations = null
      if (opts && opts.autoStake) {
        autoDelegations = state.transactions
          .filter(tr => tr.staked)
          .map(tr => ({ address: tr.current, value: tr.value }))

        if (delegationBalanceInfo.mainBalance < autoDelegations.reduce((prev, item) => (prev += item.value), 0)) {
          autoDelegations = null
        }
      }

      if (!stakeNodes.length) {
        if (autoDelegations) {
          // preview list on modal prepare
          stakeNodes = autoDelegations.map(item => ({ name: item.address, amount: item.value }))
          stakeNodes.forEach(item => {
            commit(STAKE_COIN_OPERATION.MUTATION.ADD_STAKE, item)
          })
        } else {
          stakeNodes = [{ address: state.nodes.iost[0].address, amount: delegationBalanceInfo.mainBalance }] // auto stake
        }
      }
      const rawTXs = []
      let delegations = null
      const isMultiDelegate = () => {
        const nets = ['icon', 'iost', 'cosmos', 'secret', 'band', 'kava','polkadot']
        return nets.includes(net)
      }
      // multi
      if (isMultiDelegate()) {
        delegations = stakeNodes.map(item => ({ address: item.address, value:  BigNumber(parseFloat(item.amount)).toNumber() }))
      }

      if (autoDelegations) {
        delegations = autoDelegations
      }
      
if (isMultiDelegate()) {
        // const nets = ['iost', 'cosmos', 'secret', 'band', 'kava']
        // if (nets.includes(net)) {
        //   delegations.forEach(delegate => {
        //     state.initialStakeList.forEach(initialDelegate => {
        //       if (delegate.address === initialDelegate.current) {
        //         delegate.value = BigNumber(parseFloat(delegate.value)).plus(BigNumber(parseFloat(initialDelegate.value))).toNumber()
        //       }
        //     })
        //   })
        // }
        if (net === 'icon') {
          if(state.initialStakeList.length>0){
          let value = 0
          state.initialStakeList.map(item => {
            if(state.selectedNode.address === item.current){
              value = +item.value
            }
          })
          delegations = stakeNodes.map(item => {
            if(state.selectedNode.address === item.address){
            return { address: item.address, value:  BigNumber(parseFloat(item.amount)).plus(value).toNumber() }
            }
            return { address: item.address, value:  BigNumber(parseFloat(item.amount)).toNumber() }
          })
        }
      }
      let resp 
      if(net === 'polkadot'){
        let polkaDelegations = []
        delegations.map(item => {
          polkaDelegations.push({address: item.address,value: 0})
        })
        resp = await this.$api.prepareDelegation({
          from: coin.address,
          network:  net,
          tip: opts.tip || 0,
          amount: opts.amount || 0,
          publicKey: coin.publicKey,
          delegations: polkaDelegations
        })
      }else{
        resp = await this.$api.prepareDelegation({
          from: coin.address,
          network:  net,
          publicKey: coin.publicKey,
          delegations: isMultiDelegate() ? delegations : null
        })
      }
        if (net === 'secret' || net === 'cosmos' || net === 'band' || net === 'kava') {
          rawTXs.push(resp.data.transaction)
          commit(STAKE_COIN_OPERATION.MUTATION.SET_TRANSACTIONS_FEE, resp.data.fee)
          if (opts.mainBalance < resp.data.fee) {
            commit('setfeeStakeError', true)
          }
        }else if(net === 'polkadot'){
          rawTXs.push(resp.data)
          commit(STAKE_COIN_OPERATION.MUTATION.SET_TRANSACTIONS_FEE, resp.data.fee)
        } else {
          rawTXs.push(resp.data)
        }
      } else {
        for (const node of stakeNodes) {
          let resp
          if(net === 'polkadot'){
            let totalAmount = 0
            let polkaDelegations = []
            delegations.map(item => {
              polkaDelegations.push({address: item.address,value: 0})
              totalAmount += BigNumber(item.value).toNumber()
            })
            resp = await this.$api.prepareDelegation({
              from: coin.address,
              to: node.address,
              network:  net,
              publicKey: coin.publicKey,
              amount: totalAmount,
              delegations: polkaDelegations
            })
          }else{
            resp = await this.$api.prepareDelegation({
              from: coin.address,
              to: node.address,
              network:  net,
              publicKey: coin.publicKey,
              amount: BigNumber(node.amount).toNumber(),
              delegations: isMultiDelegate() ? delegations : null
            })
          }
          
          if (net === 'secret' || net === 'cosmos' || net === 'band' || net === 'kava') {
            rawTXs.push(resp.data.transaction)
            commit(STAKE_COIN_OPERATION.MUTATION.SET_TRANSACTIONS_FEE, resp.data.fee)
            if (opts.mainBalance < resp.data.fee) {
              commit('setfeeStakeError', true)
            }
          }else if(net === 'polkadot'){
            rawTXs.push(resp.data)
            commit(STAKE_COIN_OPERATION.MUTATION.SET_TRANSACTIONS_FEE, resp.data.fee)
          } else {
            rawTXs.push(resp.data)
          }
        }
      }
      commit(STAKE_COIN_OPERATION.MUTATION.SET_RAW_TRANSACTIONS, rawTXs)
    } catch (error) {
if(error.data){
        commit(STAKE_COIN_OPERATION.MUTATION.SET_ERROR_TEXT, error.data.error)
        Sentry.captureMessage('Error in STAKE_COIN_OPERATION.ACTION.PREPARE_DELEGATION function:' + error.data)
        Sentry.captureException(error.data)
      }
    } finally {
      commit(STAKE_COIN_OPERATION.MUTATION.SET_IS_PREPARING_STAKE, false)
    }
  }
