<template>
  <div :class="$style.nodeList">
    <p>
      <i18n path="multiStake.selectOneNode">
        <span place="stake">{{ isStake ? $t('multiStake.staking') : $t('multiStake.unstaking') }}</span>
      </i18n>
    </p>
    <div :class="$style.text">
      {{ $t('stakingPage.node') }}
    </div>
    <div :class="$style.search">
      <div :class="$style.field">
        <Input ref="input" v-model="search" :placeholder="$t('stakingPage.inputTyping')" />
        <Icon icon="search" fill="#7061b6" :width="23" :height="23" :class="$style.icon" />
      </div>
    </div>

    <div :class="[$style.sort, sort && $style[`sort--${sort}`]]" @click="onSort">
      <Icon icon="sort" fill="#3F3689" :width="16" :height="16" :class="$style.icon" />
      <div :class="$style.text">
        {{ $t('stakingPage.node') }}
      </div>
    </div>
    <div v-bar="{ preventParentScroll: false, scrollThrottle: 30 }" :style="{ height: '270px' }">
      <div>
        <div
          v-for="item in slicedData"
          :key="item.key"
          :class="$style.row"
          :title="`${$t('stakingPage.nodeAddress')} ${item.key}`"
          @click="selected(!item.checked, item)"
        >
          <div :class="[$style.check, check(item) && $style.active]">
            <Icon :icon="'sidebar-form-check'" :width="14" :height="12" fill="#fff" />
          </div>
          <div :class="[$style.node, check(item) && $style.activeNode]">
            <div :class="$style.title">
              {{ item.label }}
            </div>

            <div :class="$style.tags">
              <Tag v-if="typeof item.category === 'string'" :type="item.category">
                {{ item.category }}
              </Tag>

              <template v-if="Array.isArray(item.category)">
                <Tag v-for="tag in item.category" :key="tag" :type="tag">
                  {{ tag }}
                </Tag>
              </template>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div v-if="showEmpty" :class="$style.empty">
      {{ $t('stakingPage.nodeNotInList') }}
    </div>
    <div :class="$style.row2">
      <div v-if="disabled" :class="$style.row">
        <img src="@/assets/icons/Union.svg" />
        <p :class="$style.error">{{ $t('polkadot.errorText') }}</p>
      </div>
      <button
        :class="[$style.stakeBtn, disabled && $style.disabledBtn]"
        @click="!disabled ? $emit('prepare-stake', selectedNodes) : null"
      >
        {{ isStake ? $t('stakeBtn') : $t('unstakeBtn') }}
      </button>
      <div :class="$style.controls">
        <paginate
          v-if="showPagination"
          :value="currentPage"
          :page-count="pageCount"
          prev-text="<"
          next-text=">"
          :container-class="$style.pagination"
          :page-class="$style.item"
          :active-class="$style['item--active']"
          :prev-class="$style.item"
          :next-class="$style.item"
          :click-handler="onPageChanged"
        />
      </div>
    </div>
  </div>
</template>

<script>
import { STAKE_COIN_OPERATION } from '@/store/types'
import Icon from '@/components/ui/select/Icon.vue'
import Tag from '@/components/ui/Tag.vue'
import Input from '@/components/ui/FormInput.vue'
import { sortedFunction } from '@/helpers/index'
export default {
  name: 'PolkaNodeList',
  components: {
    Icon,
    Input,
    Tag
  },
  props: {
    data: {
      type: Array,
      default: () => []
    },
    isStake: {
      type: Boolean,
      default: true
    }
  },
  data() {
    return {
      search: null,
      nodePageLimit: 10,
      startIndex: 0,
      sort: null,
      currentPage: null,
      selectedNodes: []
    }
  },
  computed: {
    dataLength() {
      return this.data ? this.data.length : 0
    },
    preparedData() {
      if (!this.isStake) {
        const nodes = []
        this.stakeList.map(node => {
          this.data.map(item => {
            if (node === item.key) {
              nodes.push(item)
            }
          })
        })
        return nodes
      } else {
        return this.data
      }
    },
    filterData() {
      return this.search
        ? [
            ...this.preparedData.filter(item => {
              const label = item.label.toLowerCase()
              const address = item.key.toLowerCase()
              const search = this.search.toLowerCase()

              return label.includes(search) || address.includes(search)
            })
          ]
        : this.preparedData
    },
    sortedData() {
      return this.sortedFunction([...this.filterData], this.sort)
    },
    slicedData() {
      return this.sortedData.slice(this.startIndex, this.startIndex + this.nodePageLimit)
    },
    pageCount() {
      const division = this.filterData.length / this.nodePageLimit

      if (division < 0) {
        return 1
      }

      if (this.filterData.length % this.nodePageLimit === 0) {
        return division
      }

      return Math.ceil(division)
    },
    stakeNodes() {
      return this.$store.getters[STAKE_COIN_OPERATION.GETTER.GET_STAKE_NODES]
    },
    selectedNode() {
      return this.$store.getters[STAKE_COIN_OPERATION.GETTER.GET_SELECTED_NODE]
    },
    showPagination() {
      return this.filterData && this.filterData.length >= 10
    },
    stakeList() {
      const stakeList = this.$store.getters[STAKE_COIN_OPERATION.GETTER.GET_STACKING_TRANSACTIONS]
      return stakeList
    },
    disabled() {
      return this.selectedNodes.length > 16
    },
    showEmpty() {
      return this.filterData && this.filterData.length === 0
    }
  },
  watch: {
    search() {
      this.startIndex = 0
      this.currentPage = 1
    }
  },
  mounted() {
    this.selected(false, { checked: false })
  },
  methods: {
    sortedFunction,
    onPageChanged(value) {
      this.startIndex = (value - 1) * this.nodePageLimit
      this.currentPage = value
    },
    selected(checked, item) {
      item.checked = checked
      this.selectedNodes = this.data.filter(coin => coin.checked)
    },
    check(item) {
      if (this.isStake) {
        return (
          this.stakeList.filter(node => node === item.key).length !== 0 ||
          this.selectedNodes.filter(node => node.label === item.label).length !== 0
        )
      } else {
        return this.selectedNodes.filter(node => node.label === item.label).length !== 0
      }
    },
    onSort() {
      if (!this.sort) {
        return (this.sort = 'asc')
      }

      if (this.sort === 'asc') {
        return (this.sort = 'desc')
      }

      return (this.sort = null)
    },
    showExists(item) {
      return (
        this.stakeNodes &&
        this.stakeNodes.length &&
        this.stakeNodes
          .filter(node => node.isStaked)
          .map(item => item.name)
          .includes(item.label)
      )
    }
  }
}
</script>

<style lang="scss" module>
.nodeList {
  position: relative;
  width: 840px;
  height: 560px;
  overflow: hidden;
  p {
    font-size: 14px;
    margin-bottom: 15px;
  }
  .check {
    margin-right: 15px;
    width: 20px;
    height: 20px;
    border: 1px solid #90a4ae;
    border-radius: 3px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .stakeBtn {
    background: linear-gradient(90.27deg, #3f3689 0%, #7061b6 100%);
    border-radius: 10px;
    color: white;
    font-weight: 700;
    height: 50px;
    font-size: 16px;
    border: none;
    outline: none;
    cursor: default;
    width: 140px;
    margin: 30px auto 20px 40%;
    cursor: pointer;
  }
  .disabledBtn {
    background: linear-gradient(95.14deg, #d2ccff 0%, #d1c4e9 0.01%, #d2ccff 100%);
    cursor: default;
  }
  .row2,
  .row {
    display: flex;
    align-items: center;
    margin-bottom: 5px;
    justify-content: space-between;
  }
  .row2 {
    justify-content: center;
    width: 100%;
    .row {
      position: absolute;
      left: 0;
      margin-top: 25px;
      img {
        margin-top: -11px;
        margin-right: 5px;
      }
    }
  }
  .text {
    color: #7061b6;
    font-weight: 700;
    font-size: 14px;
  }
  .error {
    font-size: 14px;
    line-height: 16px;
    color: #e91e63;
    position: relative;
  }
  .active {
    background-color: #3f3689;
  }
  .search {
    margin-top: 15px;
    padding-bottom: 5px;

    .label {
      padding-left: 5px;
      margin-bottom: 20px;
      color: #7061b6;
    }

    .field {
      position: relative;

      &::after {
        content: '';
        position: absolute;
        right: 50px;
        top: 8px;
        width: 1px;
        height: 35px;
        background-color: #7061b6;
        pointer-events: none;
      }

      .icon {
        position: absolute;
        right: 15px;
        top: 13px;
        pointer-events: none;
      }
    }
  }

  .sort {
    display: inline-flex;
    align-items: center;
    margin-bottom: 10px;
    margin-top: 20px;
    padding-top: 10px;
    padding-bottom: 10px;
    cursor: pointer;
    transition: opacity 0.2s;

    &:hover {
      opacity: 0.8;
    }

    .icon {
      opacity: 0.2;
      margin-right: 10px;
    }

    &--asc {
      .icon {
        opacity: 1;
        transform: rotate(180deg);
      }
    }

    &--desc {
      .icon {
        opacity: 1;
      }
    }
  }
  .activeNode {
    background-color: #673ab7;
    .title {
      color: white;
    }
  }
  .node {
    display: flex;
    align-items: center;
    border: 1px solid #f2f2f2;
    border-radius: 6px;
    padding-left: 20px;
    min-height: 55px;
    width: 95%;
    transition: background-color 0.2s;
    cursor: pointer;

    &:hover {
      background-color: #d2ccff;
    }

    &:not(:last-child) {
      margin-bottom: 10px;
    }

    .title {
      width: 50%;
      font-weight: 700;
      font-size: 14px;
      text-transform: uppercase;
    }
    .amount {
      width: 20%;
      font-size: 16px;
      display: flex;
      h2 {
        color: #a020ff;
        font-size: 16px;
        margin-right: 5px;
      }
      h3 {
        font-size: 16px;
      }
    }
    .tags {
      display: flex;
      width: 30%;
      > div:not(:last-child) {
        margin-right: 10px;
      }
    }
  }

  .empty {
    margin-top: -150px;
    padding-bottom: 30px;
    text-align: center;
  }

  .controls {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    margin-top: 40px;
    padding-bottom: 40px;

    .close {
      display: flex;
      align-items: center;
      transition: opacity 0.2s;
      cursor: pointer;

      &:hover {
        opacity: 0.6;
      }

      .text {
        margin-left: 10px;
        font-weight: bold;
        font-size: 20px;
        line-height: 20px;
        color: #3f3689;
      }
    }
  }

  .pagination {
    position: relative;
    display: flex;
    padding: 0;
    list-style: none;

    .item {
      border: solid 1px #eaeaea;
      border-radius: 3px;
      padding: 0;
      height: 28px;
      min-width: 28px;
      font-size: 14px;
      background-color: #ffffff;
      color: #3f3689;
      cursor: pointer;

      a {
        display: flex;
        justify-content: center;
        align-items: center;
        outline: none;
        width: 100%;
        height: 100%;
      }

      &:not(:last-child) {
        margin-right: 10px;
      }

      &--active {
        background-image: linear-gradient(to right, #765ebf, #42318c);
        color: #fff;
      }

      &--prev,
      &--next {
        font-weight: 500;
        font-size: 18px;
      }
    }
  }
}
</style>
