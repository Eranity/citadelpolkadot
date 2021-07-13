**Citadel.one and Polkadot interactions:**
1) Polkadot Address Generation
  The Polkadot address is generated using the Keyring class from the library "@polkadot/api"
  Encoding and decoding of a mnemonic phrase is carried out using the library "crypto-js"
  The library "bip39" is also used. 

 Polkadot wallet addition function:
    static async addNewWalletPolkadot({ type, password, opts, isFirst, mnemonic }: any): Promise<any> {
      const seed = opts.decodeSeed.data ? opts.decodeSeed.data : opts.decodeSeed
      console.log('start seed', seed)
      const keyring = new Keyring({ type: 'sr25519', ss58Format: 0 })
      let index = isFirst ? 0 : opts.coins
      const userId = opts.userId
      let localData
      let path = `//joe//polkadot//${index}`

      console.log('path!', path)
      if (userId) {
        const json = localStorage.getItem(`${userId}polkadotWalletsIndexes`)
        if (json) {
          localData = JSON.parse(json)
        }

        if (localData && localData.indexes && localData.indexes.length) {
          index = localData.indexes.shift()
        }
      }

      let backupMnemonic = ''
      if (!mnemonic) {
        // @ts-ignore
        const mnemonicFromCache = JSON.parse(localStorage.getItem(`__wallets__${userId}`)).find(item => item.type === 1)
        const bytes = CryptoJS.AES.decrypt(mnemonicFromCache.mnemonic, password)
        backupMnemonic = bytes.toString(CryptoJS.enc.Utf8)
      }

      if (opts.derrivePath) {
        path = opts.derrivePath
      }
      // console.log('mnemonic', mnemonic)
      // console.log('backupMnemonic', backupMnemonic)
      // console.log('ORR', mnemonic || backupMnemonic + path)
      let account = await keyring.addFromMnemonic(mnemonic || backupMnemonic + path)
      console.log('account', account)
      const seedNew = bip39.mnemonicToSeedSync(mnemonic || backupMnemonic + path, '')
      // const seedNew = mnemonicToMiniSecret(mnemonic || backupMnemonic + path, '')
      console.log('miniSeed', seedNew, Buffer.from(seedNew).toString('hex'))
      if (opts.privateKey) {
        console.log('private key import', opts.privateKey, Buffer.from(opts.privateKey, 'hex'))
        account = keyring.addFromSeed(Buffer.from(opts.privateKey, 'hex'))
        console.log('acccc from private key', account)
      }
      if (localData) {
        localData[account.address.toLowerCase()] = index
        localStorage.setItem(`${userId}polkadotWalletsIndexes`, JSON.stringify(localData))
      } else {
        localStorage.setItem(
          `${userId}polkadotWalletsIndexes`,
          JSON.stringify({ [account.address.toLowerCase()]: index, indexes: [] })
        )
      }
      // const { publicKey, secretKey } = naclKeypairFromSeed(seedAlice)
      console.log('ENCDOE SEED', encodeBufferByPassword(Buffer.from(seedNew, 'hex'), password))
      localStorage.setItem('polkaEncryptCode', CryptoJS.AES.encrypt(mnemonic || backupMnemonic, password).toString())
      return new KeyPair({
        coin: 'polkadot',
        address: account.address,
        type,
        // @ts-ignore
        privateKeyEncoded: CryptoJS.AES.encrypt(mnemonic || backupMnemonic, password).toString(),
        publicKey: account.publicKey
      })
    }

2) Transaction signing
Access to the wallet is obtained using a mnemonic phrase
The following libraries are also used here "crypto-js", "@polkadot/api", "@polkadot/types", "@polkadot/metadata"

  const { Keyring } = require('@polkadot/api')
  const { TypeRegistry } = require('@polkadot/types')
  const { Metadata } = require('@polkadot/metadata')
  const CryptoJS = require('crypto-js')

  console.log('oneseed')
  const account = new Keyring({ type: 'sr25519', ss58Format: 0 }).addFromMnemonic(
    // here privateKeyEncoded is a mnemonic phrase encoded.
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
