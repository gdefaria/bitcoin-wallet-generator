/*
	bitcoin addresses local generation from given entropy/mnemonic

	display mnemonic from entropy (to be backed up)
	create bip32 wallet (with password)
	show 20 p2wpkh addresses
	display hashed160 public key (so the user can verify if it matches with received utxos)

	* segwit -> m/84
	* hardened derivation
*/

// Imports
const bitcoin = require('bitcoinjs-lib')
const ecc = require('tiny-secp256k1')
const bip32 = require('bip32').BIP32Factory(ecc)
const bip39 = require('./bip39')
const { question } = require("readline-sync"); 

// User input
const getMnemonic = () => {
	const mode = question('Input mode - [E]ntropy / [m]nemonic: ')
	switch(mode.toLocaleLowerCase()) {
		case '': // default
		case 'e':
			const entropy = question('Entropy (length must be a multiple of 32):\n')
			return bip39.entropyToMnemonic(entropy)

		case 'm':
			const mnemonic = question('Mnemonic:\n')

			if (!bip39.isMnemonicValid(mnemonic))
				throw Error('Invalid mnemonic (checksum mismatched)')

			return bip39.fillMnemonicWords(mnemonic).join(' ')
			
		default:
			throw Error(`Invalid mode "${mode}. Expected 'e' / 'm'"`)
	}
}

const mnemonic = getMnemonic()
const password = question('Derivation password (Enter for no password): ')

console.log('> mnemonic seed phrase (english dictionary) =======================')
mnemonic.split(' ').forEach((word, index) => console.log(`#${index + 1} ${word}`))

// Hd Wallet
const seed = bip39.mnemonicToSeed(mnemonic, password)
const wallet = bip32.fromSeed(seed)

// Generating 20 addresses
console.log('> addresses | public key hash160 ==================================')
const parentPath = "m/84'/0'/0'/0/" // p2wpkh (BIP 84 - https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)

for (let i = 0; i < 20; i++) {
	const path = parentPath + i
	const account = wallet.derivePath(path)

	const { address, pubkey } = bitcoin.payments.p2wpkh({ pubkey: account.publicKey, network: bitcoin.networks.bitcoin })
	const hash = bitcoin.crypto.hash160(pubkey).toString('hex')

	console.log(`${path} - ${address} | ${hash}`)
}