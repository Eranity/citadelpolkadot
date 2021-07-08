<template>
  <div class="block">
    <p>{{ node.label ? node.label : 'some node' }}</p>
    <div>
      <span class="fee">{{ $t('multiStake.fee') }}:</span> <span class="number">{{ node.fee ? node.fee : 3 }}</span>
      <span class="procent">%</span>
    </div>
  </div>
</template>
<script>
export default {
  name: 'PolkaNode',
  props: {
    node: {
      type: Object,
      default: () => {}
    }
  }
}
</script>

<style lang="scss" scoped>
.block {
  display: flex;
  flex-direction: column;
  width: 45% !important;
  margin-bottom: 15px;
  p {
    font-size: 16px;
    line-height: 19px;
    color: #7061b6;
  }
  span {
    font-size: 12px;
    line-height: 14px;
  }
  .fee {
    color: #ababab;
  }
  .number {
    color: #aaa4fc;
    font-weight: 700;
  }
}
</style>
