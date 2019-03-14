// Coins supported by bitgo-bitcoinjs-lib
const typeforce = require('typeforce')

const coins = {
  BCH: 'bch',
  BSV: 'bsv',
  BTC: 'btc',
  BTG: 'btg',
  LTC: 'ltc',
  ZEC: 'zec',
  KMD: 'kmd',
  DASH: 'dash',
  DIGIBYTE: 'dgb',
  DOGECOIN: 'doge',
  NAMECOIN: 'nmc',
  VERTCOIN: 'vtc',
  CAPRICOIN: 'cpc'
}

coins.isBitcoin = function (network) {
  return typeforce.value(coins.BTC)(network.coin)
}

coins.isBitcoinCash = function (network) {
  return typeforce.value(coins.BCH)(network.coin)
}

coins.isBitcoinSV = function (network) {
  return typeforce.value(coins.BSV)(network.coin)
}

coins.isBitcoinGold = function (network) {
  return typeforce.value(coins.BTG)(network.coin)
}

coins.isLitecoin = function (network) {
  return typeforce.value(coins.LTC)(network.coin)
}

coins.isZcashLike = function (network) {
    return coins.isZcash(network) || coins.isKomodo(network)
}

coins.isZcash = function (network) {
  return typeforce.value(coins.ZEC)(network.coin)
}

coins.isKomodo = function (network) {
    return typeforce.value(coins.KMD)(network.coin)
}

coins.isDash = function (network) {
  return typeforce.value(coins.DASH)(network.coin)
}

coins.isCapricoin = function (network) {
  return typeforce.value(coins.CAPRICOIN)(network.coin)
}

coins.isValidCoin = typeforce.oneOf(
  coins.isBitcoin,
  coins.isBitcoinCash,
  coins.isBitcoinSV,
  coins.isBitcoinGold,
  coins.isLitecoin,
  coins.isZcashLike,
  coins.isZcash,
  coins.isKomodo,
  coins.isDash,
  coins.isCapricoin
)

module.exports = coins
