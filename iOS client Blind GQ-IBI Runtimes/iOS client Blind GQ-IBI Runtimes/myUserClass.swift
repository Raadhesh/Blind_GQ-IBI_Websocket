//
//  myUserClass.swift
//  iOS client Blind GQ-IBI Runtimes
//
//  Created by Raadhesh Kannan on 20/08/2023.
//

import Foundation
import CryptoSwift

class userClient {
    //MARK: Must have Variables
    var stringID:String
    var N:BigUInteger
    var e:BigUInteger
    var r:BigUInteger
    var N_hex:String
    var e_hex:String
    var r_hex:String
    var hashID:String
    var blindID:String
    
    //MARK: Secret Keys
    var sigma:String?
    var blindSigma:String?
    
    //MARK: Identification Variables
    var y:BigUInteger?
    var Y:BigUInteger?
    var CMT:String?
    var CHL:String?
    var c:BigUInteger?
    var z:BigUInteger?
    var RSP:String?
    
    //saveValue Dict
    @Published var saveDict = [String:String]()
    
    //request Dict
    @Published var requestDict = [String:String]()
    @Published var alternateRequestString:String?
    
    //upk Dict = user public key Dictionary
    @Published var upk = [String:String]()
    @Published var blind_upk = [String:String]()
    
    //usk Dict = user secret key Dictionary
    @Published var usk = [String:String]()
    @Published var blind_usk = [String:String]()
    
    
    
    //MARK: with BigUInteger and hexString inputs
    // Generate randomVal r, and default stringID conversions
    //MARK: To Generate r given N and e
    // with BigUInteger and hexString inputs
    init(stringID: String, N: BigUInteger, e: BigUInteger) {
        self.stringID = stringID
        self.N = N
        self.N_hex = hex_from_int(intVal: N)
        self.e = e
        self.e_hex = hex_from_int(intVal: e)
        self.r = generateRandomVal(maxVal: self.N)
        self.r_hex = hex_from_int(intVal: self.r)
        //hash of stringID in hexString format
        self.hashID = self.stringID.bytes.sha256().toHexString()
        self.blindID = blindFunc(randomVal: self.r, messageHex: self.hashID, e: self.e, N: self.N)
        
        self.saveDict = [
            "publicID": self.stringID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "r_hex": r_hex
        ]
        
        //not going to be called for this initialization but need to assign value due to programming constraints (mainly for my peace of mind)
        self.requestDict = [
            "request": "User Secret Key",
            "publicID": self.stringID,
            "N_hex": N_hex,
            "e_hex": e_hex
        ]
    
        self.upk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "stringID": self.stringID
        ]
        self.blind_upk = [
            "publicID": self.blindID,
            "N_hex": N_hex,
            "e_hex": e_hex
        ]
        
        
        
    }
    // with only hexString inputs
    init(stringID: String, N_hex: String, e_hex: String) {
        self.stringID = stringID
        self.N_hex = N_hex
        self.N = int_from_hex(hexString: N_hex)
        self.e_hex = e_hex
        self.e = int_from_hex(hexString: e_hex)
        self.r = generateRandomVal(maxVal: self.N)
        self.r_hex = hex_from_int(intVal: self.r)
        //hash of stringID in hexString format
//        self.hashID = self.stringID.bytes.sha256().toHexString()
        let hashID_temp = self.stringID.bytes.sha256().toHexString()
        let int_hashID_temp = int_from_hex(hexString: hashID_temp).power(1, modulus: self.N)
        self.hashID = hex_from_int(intVal: int_hashID_temp)
        
        self.blindID = blindFunc(randomVal: self.r, messageHex: self.hashID, e: self.e, N: self.N)
        
        self.saveDict = [
            "publicID": self.stringID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "r_hex": r_hex
        ]
        
        //not going to be called for this initialization but need to assign value due to programming constraints (mainly for my peace of mind)
        self.requestDict = [
            "request": "User Secret Key",
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex
        ]
        
    
        self.upk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "stringID": self.stringID
        ]
        self.blind_upk = [
            "publicID": self.blindID,
            "N_hex": N_hex,
            "e_hex": e_hex
        ]
        
        
        
    }
    
    // MARK: Requesting Blind Secret Key given parameters and r value
    // with BigUInteger and hexString inputs
    init(stringID: String, r:BigUInteger, N: BigUInteger, e: BigUInteger) {
        self.stringID = stringID
        self.N = N
        self.N_hex = hex_from_int(intVal: N)
        self.e = e
        self.e_hex = hex_from_int(intVal: e)
        self.r = r
        self.r_hex = hex_from_int(intVal: r)
        //hash of stringID in hexString format
        self.hashID = self.stringID.bytes.sha256().toHexString()
        self.blindID = blindFunc(randomVal: self.r, messageHex: self.hashID, e: self.e, N: self.N)
        
        self.saveDict = [
            "publicID": self.stringID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "r_hex": r_hex
        ]
        
        self.requestDict = [
            "request": "User Secret Key",
            "publicID": self.blindID,
            "N_hex": N_hex,
            "e_hex": e_hex
        ]
        
        self.upk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "stringID": self.stringID
        ]
        self.blind_upk = [
            "publicID": self.blindID,
            "N_hex": N_hex,
            "e_hex": e_hex
        ]
        
    }
    
    init(stringID: String, r_hex: String, N_hex: String, e_hex: String) {
        self.stringID = stringID
        self.N_hex = N_hex
        self.N = int_from_hex(hexString: N_hex)
        self.e_hex = e_hex
        self.e = int_from_hex(hexString: e_hex)
        self.r_hex = r_hex
        self.r = int_from_hex(hexString: r_hex)
        //hash of stringID in hexString format
//        self.hashID = self.stringID.bytes.sha256().toHexString()
        let hashID_temp = self.stringID.bytes.sha256().toHexString()
        let int_hashID_temp = int_from_hex(hexString: hashID_temp).power(1, modulus: self.N)
        self.hashID = hex_from_int(intVal: int_hashID_temp)
        
        self.blindID = blindFunc(randomVal: self.r, messageHex: self.hashID, e: self.e, N: self.N)
        
        self.saveDict = [
            "publicID": self.stringID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "r_hex": r_hex
        ]
        
        // decided that we always send the blinded ID for generating secret key
        self.requestDict = [
            "request": "User Secret Key",
            "publicID": self.blindID,
            "N_hex": N_hex,
            "e_hex": e_hex
        ]
        
        
        
        
        
        self.upk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "stringID": self.stringID
        ]
        self.blind_upk = [
            "publicID": self.blindID,
            "N_hex": N_hex,
            "e_hex": e_hex
        ]
        
    }
    
    // MARK: Verification using personal ID
    // with BigUInteger and hexString inputs
    init(stringID: String, sigma:String, r:BigUInteger, N: BigUInteger, e: BigUInteger) {
        self.stringID = stringID
        self.N = N
        self.N_hex = hex_from_int(intVal: N)
        self.e = e
        self.e_hex = hex_from_int(intVal: e)
        self.r = r
        self.r_hex = hex_from_int(intVal: r)
        //hash of stringID in hexString format
        self.hashID = self.stringID.bytes.sha256().toHexString()
        self.blindID = blindFunc(randomVal: self.r, messageHex: self.hashID, e: self.e, N: self.N)
        
        self.sigma = sigma
        
        self.y = generateRandomVal(maxVal: N)
        self.Y = self.y?.power(e, modulus: N)
        self.CMT = hex_from_int(intVal: self.Y!)
        let y_hex = hex_from_int(intVal: self.y!)
        
        
        self.saveDict = [
            "publicID": self.stringID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "r_hex": r_hex,
            "sigma": sigma,
            "y_hex": y_hex,
            "Y_hex": self.CMT!
        ]
        
        self.requestDict = [
            "request": "User Verification",
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "sigma": sigma,
            "CMT": self.CMT!,
            "stringID": self.stringID
        ]
        
        // upk Dict
        self.upk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "sigma": sigma,
            "stringID": self.stringID
        ]
        self.blind_upk = [
            "publicID": self.blindID,
            "N_hex": N_hex,
            "e_hex": e_hex,
        ]
        
        // usk Dict
        self.usk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "sigma": sigma,
            "stringID": self.stringID
        ]
        
    }
    
    // with only hexString inputs
    init(stringID: String, sigma:String, r_hex: String, N_hex: String, e_hex: String) {
        self.stringID = stringID
        self.N_hex = N_hex
        self.N = int_from_hex(hexString: N_hex)
        self.e_hex = e_hex
        self.e = int_from_hex(hexString: e_hex)
        self.r_hex = r_hex
        self.r = int_from_hex(hexString: r_hex)
        //hash of stringID in hexString format
        self.hashID = self.stringID.bytes.sha256().toHexString()
        self.blindID = blindFunc(randomVal: self.r, messageHex: self.hashID, e: self.e, N: self.N)
        
        self.sigma = sigma
        
        self.y = generateRandomVal(maxVal: N)
        self.Y = self.y?.power(e, modulus: N)
        self.CMT = hex_from_int(intVal: self.Y!)
        let y_hex = hex_from_int(intVal: self.y!)
        
        self.saveDict = [
            "publicID": self.stringID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "r_hex": r_hex,
            "sigma": sigma,
            "y_hex": y_hex,
            "Y_hex": self.CMT!
        ]
        
        self.requestDict = [
            "request": "User Verification",
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "sigma": sigma,
            "CMT": self.CMT!,
            "stringID": self.stringID
        ]
        
        // upk Dict
        self.upk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "stringID": self.stringID
        ]
        self.blind_upk = [
            "publicID": self.blindID,
            "N_hex": N_hex,
            "e_hex": e_hex,
        ]
        
        // usk Dict
        self.usk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "sigma": sigma,
            "stringID": self.stringID
        ]
        
    }
    
    
    // MARK: Verification using Blind ID
    // with BigUInteger and hexString inputs
    init(stringID: String, blindSigma:String, r:BigUInteger, N: BigUInteger, e: BigUInteger) {
        self.stringID = stringID
        self.N = N
        self.N_hex = hex_from_int(intVal: N)
        self.e = e
        self.e_hex = hex_from_int(intVal: e)
        self.r = r
        self.r_hex = hex_from_int(intVal: r)
        //hash of stringID in hexString format
        self.hashID = self.stringID.bytes.sha256().toHexString()
        self.blindID = blindFunc(randomVal: self.r, messageHex: self.hashID, e: self.e, N: self.N)
        
        self.blindSigma = blindSigma
        let sigma = unBlindFunc(randomVal: r, blindedMessageHex: blindSigma, e: e, N: N)
        self.sigma = sigma
        
        self.y = generateRandomVal(maxVal: N)
        self.Y = self.y?.power(e, modulus: N)
        self.CMT = hex_from_int(intVal: self.Y!)
        let y_hex = hex_from_int(intVal: self.y!)
        
        self.saveDict = [
            "publicID": self.stringID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "r_hex": r_hex,
            "blindSigma": blindSigma,
            "y_hex": y_hex,
            "Y_hex": self.CMT!
        ]
        self.requestDict = [
            "request": "Blind User Verification",
            "publicID": self.blindID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "blindSigma": blindSigma,
            "CMT": self.CMT!
        ]
        
        // upk Dict
        self.upk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "stringID": self.stringID
        ]
        self.blind_upk = [
            "publicID": self.blindID,
            "N_hex": N_hex,
            "e_hex": e_hex
        ]
        
        // usk Dict
        self.usk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "sigma": sigma,
            "stringID": self.stringID
        ]
        
        self.blind_usk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "blindSigma": blindSigma
        ]
    }
    
    // with only hexString inputs
    init(stringID: String, blindSigma:String, r_hex: String, N_hex: String, e_hex: String) {
        self.stringID = stringID
        self.N_hex = N_hex
        self.N = int_from_hex(hexString: N_hex)
        self.e_hex = e_hex
        self.e = int_from_hex(hexString: e_hex)
        self.r_hex = r_hex
        self.r = int_from_hex(hexString: r_hex)
        //hash of stringID in hexString format
        //test
        let hashID_temp = self.stringID.bytes.sha256().toHexString()
        let int_hashID_temp = int_from_hex(hexString: hashID_temp).power(1, modulus: self.N)
        self.hashID = hex_from_int(intVal: int_hashID_temp)
        
        self.blindID = blindFunc(randomVal: self.r, messageHex: self.hashID, e: self.e, N: self.N)
        
        self.blindSigma = blindSigma
        let sigma = unBlindFunc(randomVal: r, blindedMessageHex: blindSigma, e: e, N: N)
        self.sigma = sigma
        
        self.y = generateRandomVal(maxVal: N)
        self.Y = self.y?.power(e, modulus: N)
        self.CMT = hex_from_int(intVal: self.Y!)
        let y_hex = hex_from_int(intVal: self.y!)
        
        self.saveDict = [
            "publicID": self.stringID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "r_hex": r_hex,
            "blindSigma": blindSigma,
            "y_hex": y_hex,
            "Y_hex": self.CMT!
        ]
        self.requestDict = [
            "request": "Blind User Verification",
            "publicID": self.blindID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "CMT": self.CMT!
        ]
        
        let altRequestDict = [
            "request": "Blind User Verification",
            "publicID": self.blindID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "r_hex": r_hex,
            "stringID": self.stringID,
            "hashID": self.hashID,
            "blindID": self.blindID,
            "sigma": self.sigma,
            "blindSigma": self.blindSigma,
            "y_hex": y_hex,
            "Y_hex": self.CMT!,
            "CMT": self.CMT!
        ]
        self.alternateRequestString = dictionaryToJsonString(dictionary: altRequestDict)
        
        // upk Dict
        self.upk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "stringID": self.stringID
        ]
        self.blind_upk = [
            "publicID": self.blindID,
            "N_hex": N_hex,
            "e_hex": e_hex
        ]
        
        // usk Dict
        self.usk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "sigma": sigma,
            "stringID": self.stringID
        ]
        
        self.blind_usk = [
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "blindSigma": blindSigma
        ]
    }
    
    
    
}
