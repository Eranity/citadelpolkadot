import {
  SignStrategyInterface,
  SignStrategyOptionsInterface
} from '@@/lib/citadel/wallet/signing-strategies/sign-strategy.interface'
// @ts-ignore
import TransportWebUSB from '@ledgerhq/hw-transport-webusb'
import { SignData } from '@@/lib/citadel/wallet/coins'
import { newPolkadotApp } from '@@/lib/citadel/wallet/coins/polkadot/polkaFactory'
import { PostSendSignedTransaction } from '~/plugins/api/post/post-send-signed-transaction'
import { PostPolkaSignedTransaction } from '~/plugins/api/post/post-polka-sign'
import { network } from '~/plugins/api'
const { Keyring } = require('@polkadot/api')
const { TypeRegistry } = require('@polkadot/types')
const { Metadata } = require('@polkadot/metadata')
const CryptoJS = require('crypto-js')

// const { hexToU8a, u8aToHex } = require('@polkadot/util')

export class BaseSigningStrategy implements SignStrategyInterface {
  async signAndSendTransferTx(options: SignStrategyOptionsInterface<SignData>) {
    let signedTx = ''
    if (options.coin.symbol === 'dot') {
      // @ts-ignore
      if (localStorage.getItem('txType') === '2') {
        const transport = await TransportWebUSB.create()
        // @ts-ignore
        const app = newPolkadotApp(transport)
        let response = await app.getVersion()
        const pathAccount = 0x80000000
        const pathChange = 0x80000000
        // @ts-ignore
        const pathIndex = 0x8000000 + +options.coin.derrivePath
        // @ts-ignore
        const message = Buffer.from(options.data.payload, 'hex')
        console.log('signe', pathIndex, message)
        // @ts-ignore
        response = await app.sign(pathAccount, pathChange, pathIndex, options.data.transaction)
        console.log('sign ledger', response)
      } else {
        const account = new Keyring({ type: 'sr25519', ss58Format: 0 }).addFromMnemonic(
          CryptoJS.AES.decrypt(options.coin.keys.privateKeyEncoded, options.password).toString(CryptoJS.enc.Utf8)
        )
        const registry = new TypeRegistry()
        console.log('opti', options.data)
        // @ts-ignore
        const metadata = new Metadata(registry, options.data.metadata)
        registry.setMetadata(metadata)
        // @ts-ignore
        const payload = registry.createType('ExtrinsicPayload', options.data.payload)
        // @ts-ignore
        const { signature } = payload.sign(account)
        // @ts-ignore
        // let signature = account.sign(hexToU8a(options.data), { withType: true })
        // signature = JSON.stringify(u8aToHex(signature), null, 4)

        const res = await network.post(PostPolkaSignedTransaction, {
          signer: account.address,
          unsignedTx: options.data,
          // @ts-ignore
          tx: options.data.transaction,
          payload: payload.toHex(),
          // @ts-ignore
          signature
        })
        if (res.ok) {
          return res.data.hash
        } else {
          return 'Error sign transaction'
        }
      }
    } else {
      // @ts-ignore
      options.data.derrivePath = options.coin && options.coin.derrivePath
      // @ts-ignore
      signedTx = await options.coin.sign(options.data, options.password)
    }

    const res = await network.post(PostSendSignedTransaction, {
      hash: signedTx,
      network: options.network,
      from: options.coin.address
    })
    return res.data.hash || res.data.txhash
  }

  async signStackingOrDelegateTx(options: SignStrategyOptionsInterface<SignData>) {
    if (options.coin.symbol === 'dot') {
      const account = new Keyring({ type: 'sr25519', ss58Format: 0 }).addFromMnemonic(
        CryptoJS.AES.decrypt(options.coin.keys.privateKeyEncoded, options.password).toString(CryptoJS.enc.Utf8)
      )
      const registry = new TypeRegistry()
      // @ts-ignore
      const metadata = new Metadata(registry, options.data.metadata)
      registry.setMetadata(metadata)
      // @ts-ignore
      const payload = registry.createType('ExtrinsicPayload', options.data.payload)
      // @ts-ignore
      const { signature } = payload.sign(account)
      // @ts-ignore
      // let signature = account.sign(hexToU8a(options.data), { withType: true })
      // signature = JSON.stringify(u8aToHex(signature), null, 4)

      const res = await network.post(PostPolkaSignedTransaction, {
        signer: account.address,
        unsignedTx: options.data,
        // @ts-ignore
        tx: options.data.transaction,
        payload: payload.toHex(),
        // @ts-ignore
        signature
      })
      if (res.ok) {
        return res.data.hash
      } else {
        return 'Error sign transaction'
      }
    } else {
      const signedTx = await options.coin.sign(options.data, options.password)
      const { data: resp } = await network.post(PostSendSignedTransaction, {
        hash: signedTx,
        network: options.coin.network,
        from: options.coin.address
      })

      return resp.hash || resp.txhash
    }
  }
}
