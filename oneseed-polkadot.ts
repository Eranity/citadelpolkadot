// import { createAddressValidator } from '@@/lib/citadel/validators/address-validator.builder'
// import { decodeBufferByPassword } from '@@/lib/citadel/crypto'
import { KeyPair } from '../../key-pair'
import { CoinSerializedJsonData, OneseedCoinCreateOptions } from '../index'
import { OneseedEthereum } from '../ethereum'
import { BaseEthCoin } from './index'
// const crypto = require('crypto')

export class OneseedPolkadotCoin extends OneseedEthereum {
  readonly name = 'Polkadot'
  readonly symbol = 'dot'
  readonly network = OneseedPolkadotCoin.network

  static readonly canBeUsedAsWallet = true
  static readonly network = 'polkadot'

  keys: KeyPair
  // eslint-disable-next-line no-useless-constructor
  constructor(keys: KeyPair) {
    super(keys)
    this.keys = keys
  }

  sign(data: any, password: any): any {
    console.log(data, password)
    // const decodedKey = decodeBufferByPassword(this.keys.privateKeyEncoded, password)
    return data // signTxSecret(data.transaction ? data.transaction : data, decodedKey)
  }

  get address(): string {
    const address = this.keys.address
    return address
  }

  serialize(): CoinSerializedJsonData {
    return {
      address: this.address,
      // @ts-ignore
      coin: BaseEthCoin.network,
      keys: this.keys.serialize()
    }
  }

  static getTransactionUrl = (txHash: string) => `https://polkadot.subscan.io/extrinsic/${txHash}`

  static validateAddress = () => true // createAddressValidator(['1'], 48)

  static deserialize(jsonData: CoinSerializedJsonData): OneseedPolkadotCoin {
    return new OneseedPolkadotCoin(KeyPair.deserialize({ ...jsonData.keys }))
  }

  static async addNewWallet({ password, seed, mnemonic, opts }: OneseedCoinCreateOptions): Promise<any> {
    return new OneseedPolkadotCoin(
      await KeyPair.addNewWalletPolkadot({ type: 'secp256k1', password, mnemonic, seed, opts })
    )
  }

  static async create({ password, seed, mnemonic, opts }: OneseedCoinCreateOptions): Promise<any> {
    return new OneseedPolkadotCoin(
      await KeyPair.addNewWalletPolkadot({ type: 'secp256k1', password, seed, mnemonic, opts, isFirst: true })
    )
  }
}
