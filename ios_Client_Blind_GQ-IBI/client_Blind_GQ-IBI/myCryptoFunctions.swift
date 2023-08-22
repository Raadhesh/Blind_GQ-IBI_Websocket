//
//  myCryptoFunctions.swift
//  client_Blind_GQ-IBI
//
//  Created by Raadhesh Kannan on 18/08/2023.
//

import Foundation
import CryptoSwift


extension StringProtocol {
    var hexaData: Data { .init(hexa) }
    var hexaBytes: [UInt8] { .init(hexa) }
    private var hexa: UnfoldSequence<UInt8, Index> {
        sequence(state: startIndex) { startIndex in
            guard startIndex < self.endIndex else { return nil }
            let endIndex = self.index(startIndex, offsetBy: 2, limitedBy: self.endIndex) ?? self.endIndex
            defer { startIndex = endIndex }
            return UInt8(self[startIndex..<endIndex], radix: 16)
        }
    }
}


// MARK: Conversion Between BigUInt and HexString
// Convert hexString to BigUInt
public func int_from_hex(hexString: String) -> BigUInteger {
//    return BigUInteger(hexString.hexaData)
    let tempData = Data(hex: hexString)
    
    if hexString == "10001"{    // MARK: Error in Swift 5 where when I convert 10001 (hex) to 1048577 (int) instead of 65537 (int)
        print("\n\nActual int value from " + hexString + " = " + String(BigUInteger(tempData)) + "\n\n")
        return BigUInteger(65537)
        
    }
    else {
        return BigUInteger(tempData)
    }
    
}
// Convert BigUInt to hexString
public func hex_from_int(intVal: BigUInteger) -> String {
    return intVal.serialize().bytes.toHexString()
}


// MARK: Get the Document Directory URL where we store our runtime file
func getDocumentDirectory() -> URL {
    return FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
}

// MARK: Convert Seconds to Hours Minutes Seconds
public func secondsToHoursMinutesSeconds(_ seconds: Int) -> (Int, Int, Int) {
    let hour = Int(seconds / 3600)
    let min = Int(seconds % 3600) / 60
    let sec = Int((seconds % 3600) % 60)
    return (hour, min, sec)
}


// Return N,e,d parameters from newly generated RSA
public func setRSAParameters() -> (Bool, BigUInteger, BigUInteger, BigUInteger) {
    let rsa_privateKey = try! RSA(keySize: 256)    // generate rsa key
    return (true, rsa_privateKey.d!, rsa_privateKey.e, rsa_privateKey.n)
}

//MARK: Greatest Common Divisor Function
public func findGCD(num1: BigUInteger, num2: BigUInteger) -> BigUInteger {
    var x:BigUInteger = 0

   // Finding maximum number
   var y: BigUInteger = max(num1, num2)

   // Finding minimum number
   var z: BigUInteger = min(num1, num2)

   while z != 0 {
      x = y
      y = z
      z = x % y
   }
   return y
}


public func generateRandomVal(maxVal: BigUInteger) -> BigUInteger {
    var x:BigUInteger = BigUInteger.randomInteger(lessThan: maxVal)
    while findGCD(num1: x, num2: maxVal) != 1 && x > 0 {
        x = BigUInteger.randomInteger(lessThan: maxVal)
    }
    return x
}





//Check if the two values are equal and respond with approporiate STRING. Used to determine if Prover is able to successfully verify to Verifier.
public func checkIfEqual(num1: BigUInteger, num2: BigUInteger) -> Bool {
    if num1 == num2 {
        return true
    } else {
        return false
    }
}

// Blind message using r value
public func blindFunc(randomVal: BigUInteger, messageHex: String, e: BigUInteger, N: BigUInteger) -> String {
    let temp = randomVal.power(e, modulus: N)
    let tempVal = (int_from_hex(hexString: messageHex).multiplied(by: temp)).power(1, modulus: N)
    return hex_from_int(intVal: tempVal)
}

// Unblind message using r value
public func unBlindFunc(randomVal: BigUInteger, blindedMessageHex: String, e: BigUInteger, N: BigUInteger) -> String {
    
    // Convert blindSigma = blindMessageHex to BigUInt format.
    // blindSigma*(1/r) mod N
    let sigma = (int_from_hex(hexString: blindedMessageHex).multiplied(by: randomVal.inverse(N)!)).power(1, modulus: N)
    // sigma is converted to hex format and returned
    return hex_from_int(intVal: sigma)
}

// Return private key signed by the KGC with given string ID
public func signKGC(exponent: BigUInteger, N: BigUInteger, message: Array<UInt8>) -> Array<UInt8> {
    return BigUInteger(Data(message)).power(exponent, modulus: N).serialize().bytes
}

// MARK: Identification

public func genRSP_Val(c:BigUInteger, y: BigUInteger, N: BigUInteger, secretKey: String) -> BigUInteger {
    let intSecretKey = int_from_hex(hexString: secretKey)
    let z = ((intSecretKey.power(c, modulus: N)).multiplied(by: y)).power(1, modulus: N)
    return z
}
public func genRSP_Dict(z:BigUInteger) -> [String:String] {
    let z_hex = hex_from_int(intVal: z)
    let response = [
        "response":"RSP",
        "RSP": z_hex
    ]
    return response
}


