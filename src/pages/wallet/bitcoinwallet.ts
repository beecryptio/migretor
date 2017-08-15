// Copyright © 2017 Beecrypt IO Private Limited. 
// This file is part of Migretor.

// Migretor is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Migretor is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Migretor.  If not, see <http://www.gnu.org/licenses/>.
import { Injectable } from '@angular/core';
import { Http } from '@angular/http'
import { DECIMALS, Wallet, WalletURL, OfferExpiry } from './walletmodel';
import { TranslateService } from '@ngx-translate/core';
import * as btc from 'bitcoinjs-lib'
import * as BigInteger from 'bigi';
import * as Buffer from 'safe-buffer';
import * as coinselect from 'coinselect';

@Injectable()
export class BitcoinWallet extends Wallet {
	m_isTestNet: boolean = true;
	m_secretPhrase: string = '';
	m_currentNetwork: any = btc.networks.testnet;
	m_ecpair: any;
	m_balanceUpdateInProgress: boolean = false;
	m_http: Http;
	m_btcBalance: string[] = ["0", "0"];
	m_url: string;
	m_feeUrl: string = WalletURL.BTC_FEE;
	m_testnetUrl: string = WalletURL.BTC_TESTNET_BLOCK_EXPLORER;
	m_mainnetUrl: string = WalletURL.BTC_MAINNET_BLOCK_CYPHER;
	m_translate: any;
	SEQUENCE = "fffffffe";
	APPROX_SPEND_RAW_BYTES = 300;

	constructor(translate: TranslateService, http: Http) {
		super();
		this.m_http = http;
		this.m_translate = translate;
	}
  
	set testNet(isTestNet: boolean) {
		this.m_isTestNet = isTestNet;
		this.m_url = (this.m_isTestNet) ? this.m_testnetUrl : this.m_mainnetUrl;
		this.m_currentNetwork = (this.m_isTestNet)? btc.networks.testnet : btc.networks.bitcoin;
	}
	
	set secretPhrase(secret: string) {
		this.m_secretPhrase = secret;
		this.m_ecpair = new btc.ECPair(BigInteger(btc.crypto.sha256(this.m_secretPhrase).toString('hex')), null, { network: this.m_currentNetwork, compressed: true });									
		this.updateBalance();
	}
	
	get network(): any {
		return this.m_currentNetwork;
	}
	
	get hash(): string {
		return btc.crypto.sha256(Buffer.Buffer.from(this.m_secretPhrase)).toString('hex');		
	}

	isTestNet(): boolean {
		return this.m_isTestNet;
	}

	address(): string {
		return this.m_ecpair.getAddress();
	}

	publicKey(): string {
		return this.m_ecpair.getPublicKeyBuffer().toString('hex');
	}

	code(): string {
		let btc;
		this.m_translate.get('btc').subscribe(
			value => {
				btc = value;
			});
		return btc;
	}

	name(): string {
		let btc;
		this.m_translate.get('bitcoin').subscribe(
			value => {
			btc = value;
			}
		)
		return btc;
	}

	iconPath(): string {
		return "assets/icon/bitcoin.png";
	}

	balanceUpdateInProgress(): boolean {
		return this.m_balanceUpdateInProgress;
	}

	balance(): string[] {
		return this.m_btcBalance;  
	}

	decimal(): any {
		return DECIMALS.BITCOIN;
	}

	convertToBits(val): string {
		return new BigInteger('' + Math.round((val*1) * Math.pow(10, this.decimal())), 10).toString();
	}

	convertToDecimal(val): any {
		if(val) {
			let btcVal = new BigInteger(String(val));
			let afterDec = btcVal.mod(new BigInteger(String(Math.pow(10, this.decimal())))).toString();
			return btcVal.divide(new BigInteger(String(Math.pow(10, this.decimal())))).toString() 
				+ "." + "0".repeat(this.decimal() - afterDec.length) + afterDec.replace(/0+$/g, "");
		}
	}

	getAddress(publicKey: any) {
		return btc.address.toBase58Check(btc.crypto.hash160(publicKey), this.m_currentNetwork.pubKeyHash);
	}

	updateBalance() {
		let url;
		if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_CYPHER) {
			url = this.m_url + "/addrs/" + this.address() + "/balance";
		}
		if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_EXPLORER) {
			url = this.m_url + "/addr/" + this.address() + "/balance?noTxList=1&noCache=1";
		}
		this.m_http.get(url)
		.subscribe(data => {
			let balance;
			if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_CYPHER) {
				balance = this.convertToDecimal(String(data.json().final_balance)).split(".");
			}
			if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_EXPLORER) {
				balance = this.convertToDecimal(String(data.json())).split(".");
			}
			
		  this.m_btcBalance[0] = balance[0];
		  this.m_btcBalance[1] = balance[1];
		  this.m_balanceUpdateInProgress = true;
		}, error => {
		  this.m_btcBalance[0] = this.m_btcBalance[1] = "0";
		  console.log(JSON.stringify(error.json()));
		  this.m_balanceUpdateInProgress = true;
		  //show toast
		});
	}
  
	estimateEscrowFee(sendData: any, callBack: any) {
		let tempTimestamp = 1999999999;
		this.createEscrowContract(tempTimestamp, sendData.hash, sendData.pubKey, sendData.amt, sendData.fee, (response) => {
			callBack(response.fee);
		 })
	}
	
	getUTXO(address: string, callBack: any) {
		let url;
		if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_CYPHER) {
			url = this.m_url + "/addrs/" + address + "?unspentOnly=true";
		}
		if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_EXPLORER) {
			url = this.m_url + "/addr/" + address + "/utxo?noCache=1";
		}
		
		this.m_http.get(url)
		.subscribe(data => {
			let utxo = [];
			if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_CYPHER) {
				let txRefs = data.json().txrefs;
				for(let i = 0; i < txRefs.length; i++) {
					utxo.push({txId: txRefs[i].tx_hash, vout: txRefs[i].tx_output_n, value: txRefs[i].value, confirmations: txRefs[i].confirmations});
				}
			}
			if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_EXPLORER) {
				let txRefs = data.json();
				for(let i = 0; i < txRefs.length; i++) {
					utxo.push({txId: txRefs[i].txid, vout: txRefs[i].vout, value: txRefs[i].satoshis, confirmations: txRefs[i].confirmations});
				}
			}	
			callBack(utxo);
		}, error => {
			console.log(JSON.stringify(error.json()));
			//show toast
		});		
	}
	
	getTransactionForAddress(address: any, callBack: any) {
		let url;
		if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_CYPHER) {
			url = this.m_url + "/addrs/" + address;
		}
		if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_EXPLORER) {
			url = this.m_url + "/addr/" + address;
		}
		
		this.m_http.get(url)
		.subscribe(data => {
			let addressTrans = {transactions: [], totalReceivedSat: "", totalSentSat: "", balance: ""}
			if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_CYPHER) {
				let retVal = data.json();
				let txRefs = retVal.txrefs;
				for(let i = 0; i < txRefs.length; i++) {
					addressTrans.transactions.push({txId: txRefs[i].tx_hash});
				}
				addressTrans.totalReceivedSat = retVal.total_received;
				addressTrans.totalSentSat = retVal.total_sent;
				addressTrans.balance = retVal.balance;
			}
			if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_EXPLORER) {
				let txRefs = data.json();
				for(let i = 0; i < txRefs.transactions.length; i++) {
					addressTrans.transactions.push({txId: txRefs.transactions[i]});
				}
				addressTrans.totalReceivedSat = txRefs.totalReceivedSat;
				addressTrans.totalSentSat = txRefs.totalSentSat;
				addressTrans.balance = txRefs.balance;
			}	
			callBack(addressTrans);
		}, error => {
			console.log(JSON.stringify(error.json()));
			//show toast
		});				
	}
	
	getDynamicFee(callBack: any) {
		this.m_http.get(this.m_feeUrl)
		.subscribe((data: any) => {
			let fee = JSON.parse(data._body)
			console.log(fee)
			callBack(Math.floor(fee.hourFee/20));
		}, error => {
			console.log(error);
		});		
	}
	
	getScriptPubKey(a: any, b: any, finishTime: any, secret: any) {
		return btc.script.compile([
			btc.opcodes.OP_IF,
			btc.script.number.encode(finishTime),
			btc.opcodes.OP_CHECKLOCKTIMEVERIFY,	
			btc.opcodes.OP_DROP,
			Buffer.Buffer.from(a, 'hex'),
			btc.opcodes.OP_CHECKSIG,
			
			btc.opcodes.OP_ELSE,
			btc.opcodes.OP_SHA256,
			Buffer.Buffer.from(secret, 'hex'),
			btc.opcodes.OP_EQUALVERIFY,
			Buffer.Buffer.from(b, 'hex'),
			btc.opcodes.OP_CHECKSIG,
			btc.opcodes.OP_ENDIF
		]);
	}
	
  createEscrowContract(finishTime: any, secretHash: string, publicKey: string, amountNQT: string, feeNQT: string, callBack: any) {
		finishTime = String(finishTime).replace(/0x/g, '');
		secretHash = String(secretHash).replace(/0x/g, '');
		publicKey = String(publicKey).replace(/0x/g, '');
		amountNQT = String(amountNQT).replace(/0x/g, '');
		feeNQT = String(feeNQT).replace(/0x/g, '');

		this.getUTXO(this.address(), (response) => {
			this.getDynamicFee((satByte) => {
				let redeemScript = this.getScriptPubKey(this.m_ecpair.getPublicKeyBuffer().toString('hex'), publicKey, finishTime, secretHash);				
				console.log(redeemScript.toString('hex'))				
				let returnScript = btc.script.compile([btc.opcodes.OP_DUP, btc.opcodes.OP_HASH160, btc.crypto.hash160(this.m_ecpair.getPublicKeyBuffer()), btc.opcodes.OP_EQUALVERIFY, btc.opcodes.OP_CHECKSIG])
				
				let scriptPubKey = btc.script.scriptHash.output.encode(btc.crypto.hash160(redeemScript))
				let addr = btc.address.fromOutputScript(scriptPubKey, this.m_currentNetwork)
								
				let targets = [{ address: addr, value: Number(amountNQT) }];
				
				let result = coinselect(response, targets, satByte)
				if (!result.inputs || !result.outputs) return
				
				let txb = new btc.TransactionBuilder(this.m_currentNetwork)

				result.inputs.forEach(input => txb.addInput(input.txId, input.vout))
				if(result.outputs[0].address == addr) {
					txb.addOutput(scriptPubKey, result.outputs[0].value);
					txb.addOutput(returnScript, result.outputs[1].value);
				}
				
				result.inputs.forEach((_, i) => {
					txb.sign(i, this.m_ecpair)
				})

				let tx = txb.build()
				console.log(tx.toHex())
				console.log(tx);
				console.log(result.fee)
			  callBack({trans: tx, fee: result.fee, pubKey: redeemScript.toString('hex')})
			})
		})
  }
	
	createSpendContract(tx: any, secret: string, feeNQT: string, callBack: any) {
		let redeemScriptStr = btc.script.decompile(Buffer.Buffer.from(tx, 'hex'))
		let redeemScript = btc.script.compile(redeemScriptStr);
		let scriptPubKey = btc.script.scriptHash.output.encode(btc.crypto.hash160(btc.script.compile(redeemScript)))
		let address = btc.address.fromOutputScript(scriptPubKey, this.m_currentNetwork)
		this.getUTXO(address, (response) => {
			if(response) {
				let tx = new btc.TransactionBuilder(this.m_currentNetwork)
				if(!secret) {
					tx.setLockTime(btc.script.number.decode(redeemScriptStr[1]))
				}
				tx.addInput(response[0].txId, 0, 0xfffffffe)
				let scriptOut = btc.script.compile([btc.opcodes.OP_DUP, btc.opcodes.OP_HASH160, btc.crypto.hash160(this.m_ecpair.getPublicKeyBuffer()), btc.opcodes.OP_EQUALVERIFY, btc.opcodes.OP_CHECKSIG])
				this.getDynamicFee(fee => {
					let amount = (new BigInteger(String(response[0].value))).subtract(new BigInteger(String(this.APPROX_SPEND_RAW_BYTES * fee))).toString();
					tx.addOutput(scriptOut, Number(amount))

					let txRaw = tx.buildIncomplete()
					let hashType = btc.Transaction.SIGHASH_ALL
					let signatureHash = txRaw.hashForSignature(0, redeemScript, hashType)

					let redeemScriptSig;
					if(secret) {
						redeemScriptSig = btc.script.scriptHash.input.encode([
						this.m_ecpair.sign(signatureHash).toScriptSignature(hashType),
						Buffer.Buffer.from(secret),
						btc.opcodes.OP_FALSE
						], redeemScript)
					}
					else {
						redeemScriptSig = btc.script.scriptHash.input.encode([
						this.m_ecpair.sign(signatureHash).toScriptSignature(hashType),
						btc.opcodes.OP_TRUE
						], redeemScript)
					}

					txRaw.setInputScript(0, redeemScriptSig)
					console.log(txRaw.toHex());
					callBack(txRaw.toHex());						
				})
			}
		})
	}
	
	pushTx(serializedTx: string, callBack: any) {
		let pushtx, pushUrl;
		if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_CYPHER) {
			pushUrl = this.m_url + '/txs/push';
			pushtx = {
						tx: serializedTx
					};
			pushtx = JSON.stringify(pushtx);
		}
		if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_EXPLORER) {
			pushUrl = this.m_url + '/tx/send';
			pushtx = {
						rawtx: serializedTx
					};
		}
		this.m_http.post(pushUrl, pushtx, null)
		.subscribe(data => {
			console.log(data)
			if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_CYPHER) {
				callBack(data.json().tx);
			}
			if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_EXPLORER) {
				callBack({hash: data.json().txid});
			}
		}, error => {
			console.log(error);
		});		
	}
  
	exchangeContract(finishHeight: any, secretHash: string, publicKey: string, amountNQT: string, feeNQT: string, callBack: any) {
		this.createEscrowContract(finishHeight, secretHash, publicKey, amountNQT, feeNQT, (response) => {
			this.pushTx(response.trans.toHex(), (res) => {
				if(res.hash) {
					callBack({hash: response.pubKey});
				}
			});
		})
	}
  
	estimateReceiveFee(decodedTrans: any, secret: string, callBack: any) {
		this.getDynamicFee(fee => {
			callBack(this.APPROX_SPEND_RAW_BYTES * fee);
		})		
	}
  
	receiveContract(decodedTrans: any, secret: string, feeNQT: string, callBack: any) {
		this.createSpendContract(decodedTrans, secret, feeNQT, (response) => {
			let pushtx, pushUrl;
			if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_CYPHER) {
				pushUrl = this.m_url + '/txs/push';
				pushtx = {
							tx: response
						};
				pushtx = JSON.stringify(pushtx);
			}
			if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_EXPLORER) {
				pushUrl = this.m_url + '/tx/send';
				pushtx = {
							rawtx: response
						};
			}
			this.m_http.post(pushUrl, pushtx, null)
			.subscribe(data => {
				console.log(data)
				if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_CYPHER) {
					callBack(data.json().tx);
				}
				if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_EXPLORER) {
					callBack({hash: data.json().txid});
				}
			}, error => {
				console.log(error);
			});
		})
	}
	
	getTransactionDetails(transactionFullHash: string, callBack: any) {
		let url;
		if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_CYPHER) {
			url = this.m_url + "/txs/" + transactionFullHash;
		}
		if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_EXPLORER) {
			url = this.m_url + "/tx/" + transactionFullHash;
		}		
		this.m_http.get(url)
		.subscribe(data => {
			if(data.json() != "Not found") {
				let txD;
				if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_CYPHER) {
					txD = data.json();
				}
				if(this.m_url == WalletURL.BTC_TESTNET_BLOCK_EXPLORER) {
					let dataRet = data.json();
					txD = {};
					txD.inputs = [];
					for(let i = 0; i < dataRet.vin.length; i++) {
						txD.inputs.push({script: dataRet.vin[i].scriptSig.hex});
					}
					txD.outputs = [];
					for(let i = 0; i < dataRet.vout.length; i++) {
						txD.outputs.push({spent_by: dataRet.vout[i].spentTxId, addresses: dataRet.vout[i].scriptPubKey.addresses, script: dataRet.vout[i].scriptPubKey.hex});
					}
					txD.confirmations = dataRet.confirmations;
				}
				
				callBack(txD)
			}
		}, error => {
		  console.log(error);
		  callBack({"errorCode": 1});
		});
	}
	
	blockChainStatus(callBack: any) {
		this.m_http.get(this.m_url)
		.subscribe(data => {
			callBack(data.json());
		}, error => {
		  callBack({"error": true});
		  console.log(error);
		});		
	}

	escrowExpiryBlocks(callBack: any) {
			callBack(Math.floor(Date.now() / 1000) + OfferExpiry.BTC);
	}

	processHashSecretReveal(response: any, callBack: any) {
		if(response.inputs[0]) {
			let redeemScriptStr = btc.script.decompile(Buffer.Buffer.from(response.inputs[0].script, 'hex'));
			callBack(redeemScriptStr[1].toString());			
		}
		else {
			callBack();
		}
	}
}
