//
//  myWebSocketFunctions.swift
//  client_Blind_GQ-IBI
//
//  Created by Raadhesh Kannan on 18/08/2023.
//

import Foundation
import Starscream


//MARK: Conversion Between JSON String and Dictionary
// Dictionary output from jsonString input
func jsonStringToDictionary(jsonString: String) -> [String: Any]? {
    guard let jsonData = jsonString.data(using: .utf8) else {
        return nil
    }
    
    do {
        let dictionary = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any]
        return dictionary
    } catch {
        print("Error converting JSON string to dictionary: \(error.localizedDescription)")
        return nil
    }
}
// jsonString output from Dictionary Input
func dictionaryToJsonString(dictionary: [String: Any]) -> String? {
    do {
        let jsonData = try JSONSerialization.data(withJSONObject: dictionary, options: [])
        if let jsonString = String(data: jsonData, encoding: .utf8) {
            return jsonString
        }
    } catch {
        print("Error converting dictionary to JSON string: \(error.localizedDescription)")
    }
    return nil
}


// MARK: Requesting Parameters



