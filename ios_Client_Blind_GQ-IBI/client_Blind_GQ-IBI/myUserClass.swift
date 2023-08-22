//
//  myUserClass.swift
//  client_Blind_GQ-IBI
//
//  Created by Raadhesh Kannan on 18/08/2023.
//

import Foundation
import CryptoSwift

// MARK: Purpose of this class is to hold together a user's details. The user details include their id, parametes used, blinded and unblinded key pairs
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
    
    //MARK: Dictionary Variables
    //saveValue Dict
    @Published var saveDict = [String:String]()             // For Saving key user information required to regenerate user.
    
    //request Dict
    @Published var requestDict = [String:String]()
    @Published var alternateRequestString:String?           // For debugging purposes
    
    //upk Dict = user public key Dictionary
    @Published var upk = [String:String]()
    @Published var blind_upk = [String:String]()
    
    //usk Dict = user secret key Dictionary
    @Published var usk = [String:String]()
    @Published var blind_usk = [String:String]()
    
    
    // MARK: Initialization of user in userClient class
    // The class is designed to generate all information required/known by the user with the least amount of input information.
    // For simple cases to send and receive messages from the user we do not require dictionary variables like upk, usk, blind upk, and blind usk. Only requestDict is needed. But for future use case it is provided.
    // For initialization we provided two versions of the same inputs. One is using a combination of hexString and BigUInteger inputs for N, e, and r. The other is using hexString for all inputs
    
    // Currently we are using only hexString input functions
    
    
    //MARK: To Generate r given N and e
    // Only reason to call this initialization is to generate r. Suggestion: replace this with a public function. Main reason for using this is to assign r to a particular user.
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
        self.hashID = self.stringID.bytes.sha256().toHexString()
//        let hashID_temp = self.stringID.bytes.sha256().toHexString()
//        let int_hashID_temp = int_from_hex(hexString: hashID_temp).power(1, modulus: self.N)
//        self.hashID = hex_from_int(intVal: int_hashID_temp)
        
        self.blindID = blindFunc(randomVal: self.r, messageHex: self.hashID, e: self.e, N: self.N)
        
        self.saveDict = [
            "publicID": self.stringID,
            "N_hex": N_hex,
            "e_hex": e_hex,
            "r_hex": self.r_hex
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
        self.hashID = self.stringID.bytes.sha256().toHexString()
//        let hashID_temp = self.stringID.bytes.sha256().toHexString()
//        let int_hashID_temp = int_from_hex(hexString: hashID_temp).power(1, modulus: self.N)
//        self.hashID = hex_from_int(intVal: int_hashID_temp)
        
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
            // Could probably remove this and generate new Commitment Variables but we plan to store it just in case. We don't need to use it and can always generate new CMT values.
            "y_hex": y_hex,
            "Y_hex": self.CMT!
        ]
        
        self.requestDict = [
            "request": "User Verification",
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
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
            // Could probably remove this and generate new Commitment Variables but we plan to store it just in case. We don't need to use it and can always generate new CMT values.
            "y_hex": y_hex,
            "Y_hex": self.CMT!
        ]
        
        self.requestDict = [
            "request": "User Verification",
            "publicID": self.hashID,
            "N_hex": N_hex,
            "e_hex": e_hex,
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
            // Could probably remove this and generate new Commitment Variables but we plan to store it just in case. We don't need to use it and can always generate new CMT values.
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
            "sigma": sigma,
            "stringID": self.stringID
        ]
        
        self.blind_usk = [
            "publicID": self.hashID,
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
            "N_hex": self.N_hex,
            "e_hex": self.e_hex,
            "r_hex": self.r_hex,
            "blindSigma": self.blindSigma!,
            // Could probably remove this and generate new Commitment Variables but we plan to store it just in case. We don't need to use it and can always generate new CMT values.
            "y_hex": y_hex,
            "Y_hex": self.CMT!
        ]
        self.requestDict = [
            "request": "Blind User Verification",
            "publicID": self.blindID,
            "N_hex": self.N_hex,
            "e_hex": self.e_hex,
            "CMT": self.CMT!
        ]
        
        let altRequestDict = [
            "request": "Blind User Verification",
            "publicID": self.blindID,
            "N_hex": self.N_hex,
            "e_hex": self.e_hex,
            "r_hex": self.r_hex,
            "stringID": self.stringID,
            "hashID": self.hashID,
            "blindID": self.blindID,
            "sigma": self.sigma,
            "blindSigma": self.blindSigma,
            "y_hex": y_hex,
            "Y_hex": self.CMT!,
            "CMT": self.CMT!
        ]
        // reason for not doing the same for request dict is to test request Dict in terms of what will happen if you assign the wrong value.
        self.alternateRequestString = dictionaryToJsonString(dictionary: altRequestDict as [String : Any])
        
        // upk Dict
        self.upk = [
            "publicID": self.hashID,
            "N_hex": self.N_hex,
            "e_hex": self.e_hex,
            "stringID": self.stringID
        ]
        self.blind_upk = [
            "publicID": self.blindID,
            "N_hex": self.N_hex,
            "e_hex": self.e_hex
        ]
        
        // usk Dict
        self.usk = [
            "publicID": self.hashID,
            "sigma": self.sigma!,
            "stringID": self.stringID
        ]
        
        self.blind_usk = [
            "publicID": self.hashID,
            "blindSigma": self.blindSigma!
        ]
    }
    
    
    
}
