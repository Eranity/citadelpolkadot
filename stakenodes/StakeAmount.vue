<template>
  <div>
    <div class="nodes-table-row">
      <div class="nodes-table-cell justify-start">
        <div class="column">
          <div>
            <span v-if="index == -1" class="stake-color"></span>
            <span v-else class="stake-color" style="background-color:#FF5722"></span>
            <h1>{{ node.name }}</h1>
          </div>
        </div>
        <p v-if="false" class="fee-p">{{ $t('multiStake.fee') }}: <span>3</span>%</p>
      </div>
      <div class="delimeter"></div>
      <div class="nodes-table-cell">
        <div class="balance-div">
          <!-- eslint-disable-next-line -->
        <h1 v-html="getHtmlBalance(numberFormatterByCurrency(node.amount) + '')"></h1>
          <span>{{ getSymbol() }}</span>
        </div>
        <p>
          {{ $t('multiStake.balanceShare') }}: <span> {{ ((node.amount / totalCalculate) * 100).toFixed(2) }}</span
          >%
        </p>
      </div>
    </div>
    <div class="row">
      <p>Polkadot One Seed</p>
      <Info class="info-helper" :light="true" :width="350">
        <template #title>
          <span>{{ $route.params.walletAddress || $route.params.address }}</span>
        </template>
      </Info>
      <p v-if="false" class="blue">{{ $t('polkadot.withRestake') }}</p>
    </div>
  </div>
</template>

<script>
import { formatAddress } from '@@/lib/formatters/address'
import { getHtmlBalance } from '@/helpers/balanceHtml'
import Info from '@/components/ui/Info.vue'
import { numberFormatterByCurrency } from '@/helpers/numerals'
import { INTERNAL_WALLET, WALLET, STAKE_COIN_OPERATION } from '@/store/types'
export default {
  name: 'StakeAmount',
  components: { Info },
  props: {
    node: {
      type: Object,
      default: () => {}
    },
    index: {
      type: Number,
      default: 0
    },
    totalCalculate: {
      type: Number,
      default: 0
    }
  },
  data: () => ({}),
  computed: {
    selectedCoin() {
      const currWallet = this.$store.getters[INTERNAL_WALLET.GETTER.GET_SELECTED_COIN]
      const wallets = this.$store.getters[WALLET.GETTER.GET_WALLETS]
      const net = this.$route.params.currencyCode || this.$route.params.coin
      if (!currWallet) {
        const w = wallets.find(
          w =>
            w.address &&
            w.address.toLowerCase() === this.$route.params.walletAddress.toLowerCase() &&
            w.net === net.toLowerCase()
        )
        return {
          ...w,
          network: w.net,
          symbo: w.currency.code
        }
      }

      return currWallet
    }
  },
  methods: {
    formatAddress,
    getHtmlBalance,
    numberFormatterByCurrency,
    getSymbol() {
      let symbol = this.selectedCoin.symbol || this.selectedCoin.currency.code
      if (symbol === 'cosmos') return 'ATOM'
      if (this.currentToken && this.currentToken.net === 'eth_orbs') {
        symbol = 'orbs'
      }
      return symbol.toUpperCase()
    },
    openEditModal() {
      this.$store.commit(STAKE_COIN_OPERATION.MUTATION.SET_STAKE_MODAL_OPEN, true)
      this.$store.commit(STAKE_COIN_OPERATION.MUTATION.SET_SELECTED_NODE, this.node)
      this.$store.commit(STAKE_COIN_OPERATION.MUTATION.SET_EDIT_NODE, true)
    }
  }
}
</script>

<style lang="scss" scoped>
.nodes-table-row {
  padding-top: 15px;
  padding-bottom: 15px;
  &:hover {
    background: #f9faff;
  }
}
.nodes-table-cell {
  color: #3f3689;
  display: flex;
  flex-direction: column;
  .balance-div {
    h1 {
      color: #a020ff !important;
      font-weight: 500;
      font-size: 17px;
      margin-right: 5px;
    }
    span {
      color: black;
      font-weight: 300;
    }
  }
  .column {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    justify-content: flex-start;
  }
}
.row {
  padding-left: 20px;
  margin: -25px auto 0 20px;
  display: flex;
  padding-bottom: 10px;
  p {
    font-weight: 500;
    font-size: 14px;
    line-height: 19px;
    color: #3f3689;
  }
  .blue {
    color: #008de4;
  }
}
.delimeter {
  position: relative;
  top: -8px;
  flex: 1 0 auto;
  border-bottom: 1px dashed #dadada;
  margin: auto -10px auto;
}
.info-helper {
  position: relative;
  top: 5px;
  margin-left: 5px;
  margin-right: 5px;
  span {
    color: gray;
    font-size: 12px;
  }
}
.justify-start {
  justify-content: flex-start !important;
}

.nodes-table {
  width: 100%;
  margin-right: 20px;
  &-body > *:not(:last-child) {
    margin-bottom: 10px;
  }

  &-row {
    display: flex;
    padding-left: 20px;
    justify-content: space-between;

    & > * {
      margin-right: 20px;
    }

    & > :first-child {
      width: 25%;
    }
    & > :nth-child(2) {
      width: 50%;
    }
    & > :nth-child(3) {
      width: 18%;
    }
  }
  .row-without {
    background: #e2f3ff;
  }
  &-cell {
    display: flex;
    justify-content: left;
    p {
      color: #ababab;
      font-size: 12px;
      margin-top: 10px;
      span {
        color: #aaa4fc;
        font-weight: bold;
      }
    }
    .fee-p {
      margin-left: 20px;
    }
    button {
      background: rgba(242, 104, 34, 0.1);
      border-radius: 6px;
      border: none;
      color: #ff5722;
      font-weight: 900;
      height: 34px;
      width: auto;
      padding-left: 10px;
      padding-right: 10px;
      white-space: nowrap;
      cursor: pointer;
      outline: none;
    }
    div {
      display: flex;
      align-items: center;
      h1 {
        color: black;
        font-weight: bold;
        font-size: 17px;
        text-transform: uppercase;
      }
      .stake-color {
        display: block;
        background-color: #888888;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 10px;
      }
    }
  }
}
</style>
