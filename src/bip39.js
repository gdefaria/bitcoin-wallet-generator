const fs = require('fs')
const { createHash, pbkdf2Sync } = require('crypto')

const wordlist = fs
.readFileSync('./wordlists/english.txt')
.toString('ascii')
.split('\n')

const checksum = (buff) => (
	createHash('sha256')
	.update(buff)
	.digest()
)

const binaryStringToBuffer = binary => {
	const byteStr = binary.match(/.{1,8}/g) || []
	const byteArray = byteStr.map(str => parseInt(str, 2))

	return Uint8Array.from(byteArray)
}

const bufferToBinaryString = buff => {
	let binaryString = ''

	for (const byte of buff) {
		binaryString += byte.toString(2).padStart(8, '0')
	}

	return binaryString
}

function fillMnemonicWords(mnemonic) {
	const filledMnemonic = []

	for (let word of mnemonic.split(' ')) {		
		if (word.length < 4) {
			filledMnemonic.push(word)
			continue
		}
		
		const candidateWords = wordlist.filter(listWord => listWord.startsWith(word))

		if (candidateWords.length === 0) throw Error(`Unknown word: ${word}`)
		if (candidateWords.length > 1) throw Error(`Ambiguous incomplete word: ${word}. Possible entries: ${candidateWords.join(', ')}`)
		
		filledMnemonic.push(candidateWords[0])
	}

	return filledMnemonic
}

function isMnemonicValid(mnemonic) {
	const words = fillMnemonicWords(mnemonic)
	let binaryMnemonic = ''

	for (let word of words) {
		const index = wordlist.indexOf(word)
		const binaryRepresentation = index.toString(2).padStart(11, '0')
		binaryMnemonic += binaryRepresentation
	}

	// verifying checksum
	const checkSize = binaryMnemonic.length / 32
	const entropy = binaryMnemonic.slice(0, -checkSize)
	const check = binaryMnemonic.slice(-checkSize)
	const expectedCheck = bufferToBinaryString( checksum(binaryStringToBuffer(entropy)) )

	return expectedCheck.startsWith(check)
}

function entropyToMnemonic(entropy) {
	if (entropy.length % 32 !== 0)
		throw Error('Entropy must be a multiple of 32')

	const entropyBuff = binaryStringToBuffer(entropy)
	
	const check = checksum(entropyBuff)
	const checkSize = entropy.length / 32
	const checkChunk = bufferToBinaryString(check).slice(0, checkSize)

	const seed = entropy + checkChunk
	let mnemonic = []

	for (let i = 0; i < seed.length; i += 11) {
		const index = parseInt(seed.slice(i, i + 11), 2)
		mnemonic.push(wordlist[index])
	}

	return mnemonic.join(' ')
}

function mnemonicToSeed(mnemonic, password='') {
	if (!isMnemonicValid(mnemonic))
		throw Error('Checksum mismatched')

	// deriving seed
	const digest = pbkdf2Sync(
		mnemonic,
		`mnemonic${password}`,
		2048,
		64,
		'sha512'
	)

	return digest
}

module.exports = {
	entropyToMnemonic,
	mnemonicToSeed,
	isMnemonicValid,
	fillMnemonicWords,
}