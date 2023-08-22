//
//  myVariables.swift
//  client_Blind_GQ-IBI
//
//  Created by Raadhesh Kannan on 18/08/2023.
//

import Foundation
import Starscream
import CryptoSwift

//var requestParamsDict = [
//    "request": "Public Parameters",
//    "message": "This is the iOS Client"
//]




// MARK: Instead of using class initialization, we are using functions.
public func genSaveDict(stringID: String, N: BigUInteger, e: BigUInteger) -> [String:String] {
    let hashID = stringID.bytes.sha256().toHexString()
    let r = generateRandomVal(maxVal: N)
    let blindID = blindFunc(randomVal: r, messageHex: hashID, e: e, N: N)
    let saveDict = [
        "publicID": hashID,
        "N_hex": hex_from_int(intVal: N),
        "e_hex": hex_from_int(intVal: e),
        "r_hex": hex_from_int(intVal: r),
        "blindID": blindID,
        "stringID":stringID
    ]
    return saveDict
}

public func genSaveDict(stringID: String, r:BigUInteger, N: BigUInteger, e: BigUInteger) -> [String:String] {
    let hashID = stringID.bytes.sha256().toHexString()
    let blindID = blindFunc(randomVal: r, messageHex: hashID, e: e, N: N)
    let saveDict = [
        "publicID": stringID,
        "N_hex": hex_from_int(intVal: N),
        "e_hex": hex_from_int(intVal: e),
        "r_hex": hex_from_int(intVal: r),
        "blindID": blindID,
        "stringID":stringID
    ]
    return saveDict
}

//when all inputs are in hexString format
public func genSaveDict(stringID: String, N_hex: String, e_hex: String) -> [String:String] {
    let hashID = stringID.bytes.sha256().toHexString()
    let N = int_from_hex(hexString: N_hex)
    let e = int_from_hex(hexString: e_hex)
    let r = generateRandomVal(maxVal: N)
    let blindID = blindFunc(randomVal: r, messageHex: hashID, e: e, N: N)
    let saveDict = [
        "publicID": stringID,
        "N_hex": hex_from_int(intVal: N),
        "e_hex": hex_from_int(intVal: e),
        "r_hex": hex_from_int(intVal: r)
    ]
    return saveDict
}

public func genSaveDict(stringID: String, r_hex:String, N_hex: String, e_hex: String) -> [String:String] {
    let hashID = stringID.bytes.sha256().toHexString()
    let N = int_from_hex(hexString: N_hex)
    let e = int_from_hex(hexString: e_hex)
    let r = int_from_hex(hexString: r_hex)
    let blindID = blindFunc(randomVal: r, messageHex: hashID, e: e, N: N)
    let saveDict = [
        "publicID": stringID,
        "N_hex": hex_from_int(intVal: N),
        "e_hex": hex_from_int(intVal: e),
        "r_hex": hex_from_int(intVal: r)
    ]
    return saveDict
}
