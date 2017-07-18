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
import * as Buffer from 'buffer';

class UTXO {
	m_tx: any;
	m_index: any;
	m_script: any;
	
	constructor(tx: any, index: any, script: any) {
		this.m_tx = tx;
		this.m_index = index;
		this.m_script = script;
	}
	
	set script(srpt: any) {
		this.m_script = srpt;
	}
}

class OutTx {
	m_script: any;
	m_value: any;
	
	constructor(script: any, value: any) {
		this.m_script = script;
		this.m_value = value;
	}
}

class BTCTransaction {
	VERSION: string = "01000000";
	SEQUENCE: string = "ffffffff";
	LOCK_TIME: string = "00000000";
	HASH_TYPE: string = "01000000";
	
	m_utxo: Array<UTXO> = new Array<UTXO>();
	m_outs: Array<OutTx> = new Array<OutTx>();
	
	m_btcTx: string = "";
	
	constructor() {
	}

	addInput(tx: any, index: any, script: any) {
		this.m_utxo.push(new UTXO(tx, index, script));
	}
	
	addOutput(script: any, value: any) {
		this.m_outs.push(new OutTx(script, value));
	}
	
	serialize(): string {
		this.m_btcTx = this.VERSION;
		let numIn = BigInteger(String(this.m_utxo.length)).toBuffer().toString('hex');
		this.m_btcTx += numIn;
		for(let i = 0; i < this.m_utxo.length; i++) {
			this.m_btcTx += this.m_utxo[i].m_tx.toString('hex') + 
				(this.m_utxo[i].m_index.toString('hex') + "0".repeat(8)).slice(0,8) + 
				Buffer.Buffer.from([this.m_utxo[i].m_script.length/2]).toString('hex') +
				this.m_utxo[i].m_script.toString() + this.SEQUENCE;
		}
		
		let numOut = BigInteger(String(this.m_outs.length)).toBuffer().toString('hex');
		this.m_btcTx += numOut;
		
		for(let j = 0; j < this.m_outs.length; j++) {
			this.m_btcTx += (this.m_outs[j].m_value.toBuffer().reverse().toString('hex') + "0".repeat(16)).slice(0, 16) + 
				Buffer.Buffer.from([this.m_outs[j].m_script.length/2]).toString('hex') +
				this.m_outs[j].m_script.toString()
		}
		
		this.m_btcTx += this.LOCK_TIME + this.HASH_TYPE;
		return this.m_btcTx;
	}
	
	clone(): BTCTransaction {
		let tx = new BTCTransaction();
		for(let i = 0; i < this.m_utxo.length; i++) {
			tx.addInput(this.m_utxo[i].m_tx, this.m_utxo[i].m_index, this.m_utxo[i].m_script)
		}

		for(let j = 0; j < this.m_outs.length; j++) {
			tx.addOutput(this.m_outs[j].m_script, this.m_outs[j].m_value)
		}
		
		return tx;
	}
	
	getTxHash(index: any) {
		let tx = this.clone();
		for(let i = 0; i < tx.m_utxo.length; i++) {
			if(i != index) {
				tx.m_utxo[i].script = [];
			}
		}
		let txBuf = new Buffer.Buffer(tx.serialize(), 'hex')
		return btc.crypto.hash256(txBuf);
	}
}

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
	m_testnetUrl: string = WalletURL.BTC_TESTNET
	m_mainnetUrl: string = WalletURL.BTC_MAINNET;
	m_translate: any;

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
	
	set secretPhrase(secretPhrase: string) {
		this.m_secretPhrase = secretPhrase;
		this.m_ecpair = new btc.ECPair(BigInteger.fromBuffer(btc.crypto.sha256(this.m_secretPhrase)), 
									null, { network: this.m_currentNetwork, compressed: true });
		this.updateBalance();
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
			}
		);
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
		let btcVal = new BigInteger(String(val));
		let afterDec = btcVal.mod(new BigInteger(String(Math.pow(10, this.decimal())))).toString();
		return btcVal.divide(new BigInteger(String(Math.pow(10, this.decimal())))).toString() 
			+ "." + "0".repeat(this.decimal() - afterDec.length) + afterDec.replace(/0+$/g, "");
	}

	getAddress(publicKey: any) {
		return btc.address.toBase58Check(btc.crypto.hash160(publicKey), this.m_currentNetwork.pubKeyHash);
	}

	updateBalance() {
		let url = this.m_url + "/addrs/" + this.address() + "/balance";
		this.m_http.get(url)
		.subscribe(data => {
		  let balance = this.convertToDecimal(String(data.json().final_balance)).split(".");
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
		this.createEscrowContract(tempTimestamp, sendData.hash, sendData.pubKey, sendData.amt, sendData.fee, (response)=> {
			this.m_http.get(this.m_feeUrl)
			.subscribe((data: any) => {
			  let fee = JSON.parse(data._body)
			  console.log(fee)
			  callBack(fee.hourFee * (response.tx.length / 2));
			}, error => {
			  callBack({"error": true})
			  console.log(JSON.stringify(error.json()));
			});	
		})
	}
	
  createEscrowContract(finishHeight: any, secretHash: string, publicKey: string, amountNQT: string, feeNQT: string, callBack: any) {
		finishHeight = String(finishHeight).replace(/0x/g, '');
		secretHash = String(secretHash).replace(/0x/g, '');
		publicKey = String(publicKey).replace(/0x/g, '');
		amountNQT = String(amountNQT).replace(/0x/g, '');
		feeNQT = String(feeNQT).replace(/0x/g, '');
		let url = this.m_url + "/addrs/" + this.address() + "?unspentOnly=true";
		this.m_http.get(url)
		.subscribe(data => {
			let scriptPubKey = btc.script.compile([btc.opcodes.OP_DUP, btc.opcodes.OP_HASH160, btc.crypto.hash160(this.m_ecpair.getPublicKeyBuffer()), btc.opcodes.OP_EQUALVERIFY, btc.opcodes.OP_CHECKSIG])
			let script = Buffer.Buffer.from(scriptPubKey.toString('hex'));
			let amountToSpend = new BigInteger(String(amountNQT));
			let fee = new BigInteger(String(feeNQT));
			amountToSpend = amountToSpend.add(fee);
			let txValues = BigInteger.ZERO;
			let txRefs = data.json().txrefs;
			let btcTx = new BTCTransaction();
			for(let i = 0; i < txRefs.length; i++) {
				txValues = txValues.add(new BigInteger(String(txRefs[i].value)));

				let prevTxBuf = (new Buffer.Buffer(txRefs[i].tx_hash, "hex")).reverse();
				let outIndex = new BigInteger(String(txRefs[i].tx_output_n)).toBuffer().reverse();
				
				btcTx.addInput(prevTxBuf, outIndex, script)
				if(amountToSpend.compareTo(txValues) <= 0) {
				  break;
				}
			}
			
			let scriptOut = btc.script.compile([btc.opcodes.OP_IF, btc.script.number.encode(finishHeight), btc.opcodes.OP_CHECKLOCKTIMEVERIFY, btc.opcodes.OP_DROP, this.m_ecpair.getPublicKeyBuffer(), btc.opcodes.OP_CHECKSIG, btc.opcodes.OP_ELSE , btc.opcodes.OP_SHA256, Buffer.Buffer.from(secretHash, 'hex'), btc.opcodes.OP_EQUALVERIFY, Buffer.Buffer.from(publicKey, 'hex'), btc.opcodes.OP_CHECKSIG, btc.opcodes.OP_ENDIF])
			let outScript = Buffer.Buffer.from(scriptOut.toString('hex'));
			
			let returnValue = txValues.subtract(amountToSpend);
			if(returnValue.compareTo(BigInteger.ZERO) != 0) {
				btcTx.addOutput(script, returnValue);
			}
			btcTx.addOutput(outScript, amountToSpend.subtract(fee));
			
			for(let i = 0; i < btcTx.m_utxo.length; i++) {
				let bufDER = this.m_ecpair.sign(btcTx.getTxHash(i)).toDER();
				let hashCodeType = new Buffer.Buffer("01", "hex");
				let derPlusHashCodeLen = Buffer.Buffer.from([bufDER.length + hashCodeType.length]);
				let pubKeyLen = Buffer.Buffer.from([this.m_ecpair.getPublicKeyBuffer().length])
				let sig = Buffer.Buffer.concat([derPlusHashCodeLen, bufDER, hashCodeType, pubKeyLen, this.m_ecpair.getPublicKeyBuffer()]);
				btcTx.m_utxo[i].m_script = Buffer.Buffer.from(sig.toString('hex'));
			}

			let serializedTx = btcTx.serialize()
			console.log(serializedTx)
			let pushtx = {
			  tx: serializedTx.slice(0, (serializedTx.length - 8))
			};
 
			callBack(pushtx);
		}, error => {
			console.log(JSON.stringify(error.json()));
			//show toast
		});
  }
  
	exchangeContract(finishHeight: any, secretHash: string, publicKey: string, amountNQT: string, feeNQT: string, callBack: any) {
		this.createEscrowContract(finishHeight, secretHash, publicKey, amountNQT, feeNQT, (pushtx) => {
		let pushUrl = this.m_url + '/txs/push';		
		this.m_http.post(pushUrl, JSON.stringify(pushtx), null)
		  .subscribe(data => {
			console.log(data)
			callBack(data.json().tx);
		  }, error => {
			console.log(JSON.stringify(error.json()));
		  });		  
		})
	}
  
	createSpendContract(decodedTrans: any, secret: string, feeNQT: string, callBack: any) {
		let payOnHashRevealIndex = 1;
		if(decodedTrans.outputs[payOnHashRevealIndex] && decodedTrans.outputs[payOnHashRevealIndex].value && decodedTrans.outputs[payOnHashRevealIndex].script) {
			let inputIndex = 0;
			let prevTxBuf = (new Buffer.Buffer(decodedTrans.hash, "hex")).reverse();
			let outIndex = Buffer.Buffer.from("01000000", "hex");
			let scriptPubKey = Buffer.Buffer.from(decodedTrans.outputs[payOnHashRevealIndex].script); //output to be redeemed
			let btcTx = new BTCTransaction();
			btcTx.addInput(prevTxBuf, outIndex, scriptPubKey);
			let fee = new BigInteger(String(feeNQT));
			let outVal = (new BigInteger(String(decodedTrans.outputs[payOnHashRevealIndex].value))).subtract(fee);			
			let scriptOut = btc.script.compile([ btc.opcodes.OP_DUP, btc.opcodes.OP_HASH160, btc.crypto.hash160(this.m_ecpair.getPublicKeyBuffer()), btc.opcodes.OP_EQUALVERIFY, btc.opcodes.OP_CHECKSIG ])
			let script = Buffer.Buffer.from(scriptOut.toString('hex'));
			btcTx.addOutput(script, outVal)
			let bufDER = this.m_ecpair.sign(btcTx.getTxHash(inputIndex)).toDER();
			let hashCodeType = new Buffer.Buffer("01", "hex");
			let derPlusHashCodeLen = Buffer.Buffer.from([bufDER.length + hashCodeType.length]);
			let redeemScriptCompile = btc.script.compile([Buffer.Buffer.from(secret), btc.opcodes.OP_0]);
			let signature = Buffer.Buffer.concat([derPlusHashCodeLen, bufDER, hashCodeType, redeemScriptCompile])
			btcTx.m_utxo[inputIndex].m_script = Buffer.Buffer.from(signature.toString('hex'));	
			
			let serializedTx = btcTx.serialize()
			console.log(serializedTx)
			callBack(serializedTx.slice(0, (serializedTx.length - 8)));
		}
	}
  
	estimateReceiveFee(decodedTrans: any, secret: string, callBack: any) {
		this.createSpendContract(decodedTrans, secret, "000000", (response) => {
		this.m_http.get(this.m_feeUrl)
		.subscribe((data: any) => {
		  let fee = JSON.parse(data._body)
		  console.log(fee)
		  callBack(fee.hourFee * (response.toString('hex').length / 2));
		}, error => {
		  console.log(JSON.stringify(error.json()));
		});		  
		})
	}
  
	receiveContract(decodedTrans: any, secret: string, feeNQT: string, callBack: any) {
		this.createSpendContract(decodedTrans, secret, feeNQT, (response) => {
			let pushtx = {
				tx: response.toString('hex')
			};
			let pushUrl = this.m_url + '/txs/push';

			this.m_http.post(pushUrl, JSON.stringify(pushtx), null)
			.subscribe(data => {
			console.log(data)
			callBack(data.json().tx);
			}, error => {
			console.log(JSON.stringify(error.json()));
			});
		})
	}
  
	getTransactionDetails(transactionFullHash: string, callBack: any) {
		let url = this.m_url + "/txs/" + transactionFullHash;
		this.m_http.get(url)
		.subscribe(data => {
		  callBack(data.json())
		}, error => {
		  console.log(JSON.stringify(error.json()));
		  callBack({"errorCode": 1});
		});
	}
	
	blockChainStatus(callBack: any) {
		this.m_http.get(this.m_url)
		.subscribe(data => {
			callBack(data.json());
		}, error => {
		  callBack({"error": true});
		  console.log(JSON.stringify(error.json()));
		});		
	}

	escrowExpiryBlocks(callBack: any) {
		this.blockChainStatus(response => {
			callBack((parseInt(response.height) + OfferExpiry.BTC_BLOCKS));
		})
	}

	processHashSecretReveal(response: any, callBack: any) {
		let scriptData = new Buffer.Buffer(response.inputs[0].script, 'hex');
		let sigDataLength = scriptData[0] + 2;
		let secretPos = scriptData.slice(sigDataLength - 1, sigDataLength); //First byte will give sig data length, after sig data length 1 byte is secret pos length

		callBack(scriptData.slice(sigDataLength, sigDataLength + secretPos[0]).toString());
	}
}
