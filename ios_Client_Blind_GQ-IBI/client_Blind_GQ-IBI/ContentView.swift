//
//  ContentView.swift
//  client_Blind_GQ-IBI
//
//  Created by Raadhesh Kannan on 18/08/2023.
//

import SwiftUI
import Starscream
import CryptoSwift


// Screen width.
public var screenWidth: CGFloat {
    return UIScreen.main.bounds.width
}


//MARK: Variables for saving text file storing currentDict
//let deviceName:String = UIDevice.current.name
//let runtimeFileName = deviceName + " Blind GQ-IBI currentDict" + ".txt"
//let runtimePath = getDocumentDirectory().appendingPathComponent(runtimeFileName)

//MARK: Request Parameters JSON
var requestParamsDict = [
    "request": "Public Parameters",
    "message": "This is the iOS Client"
]


//MARK: Declaring Variables needed by entire file
let seconds = 1.0
// we are declaring the parameters here to make it accessible to the whole file.
var e:BigUInteger?
var N:BigUInteger?
var e_hex:String?
var N_hex:String?
var r:BigUInteger?
var r_hex:String?

var stringID:String = ""
var hashID:String = ""
var blindID:String = ""

var sigma:String = ""
var blindSigma:String = ""

//For Identificaton
var y:BigUInteger?
var Y:BigUInteger?
var CMT:String?
var CHL:String?
var c:BigUInteger?
var z:BigUInteger?
var RSP:String?

//MARK: For finding runtime
var totalTimeTaken:Double = 0
var getParametersTime:Double = 0
var extractPrepTime:Double = 0
var getBlindSecretKeyTime:Double = 0
var getUnBlindSecretKeyTime:Double = 0
var blindIdentificationTime: Double = 0

struct ContentView: View {
    let totalStartTime = Date()
    //MARK: Declaring WebSocket
    // Using ngrok to broadcast server ip ("http://localhost:8765")
    @StateObject var ws = webSocketManager(givenStringURL: "https://b280-203-106-65-210.ngrok-free.app")
    @State var requestParamsJSON = dictionaryToJsonString(dictionary: requestParamsDict)
    @State var dictMSG = [String:Any]()
    
    //MARK: Declaring Boolean Checks to display Views
    @State var currentUserDict = [String:String]()
    @State var nameTextField = ""
    @State var receiveParamCheck = false
    @State var extractPrepCheck = false
    @State var extractPostCheck = false
    @State var identificationCheck = false
//    @State var identificationPrepCheck = false
//    @State var identificationPostCheck = false
    @State var identitySuccess:Bool?
    
    var body: some View {
        ScrollView {
            
            //MARK: Get Public Parameters
            VStack{
                
                Text("Get Parameters").font(.largeTitle)
                Button("Request Message") {
                    let paramStartTime = Date()
                    print("\nRequest Message Button Pressed\n")
                    ws.socket.write(string: requestParamsJSON!)
                    print("Request has been sent to Python Server\n")
                    
                    
                    
                    DispatchQueue.main.asyncAfter(deadline: .now() + seconds) {
                        // Put your code which should be executed with a delay here

                        let tempParam = jsonStringToDictionary(jsonString: ws.receivedMessage)!
                        print("tempParam = \(tempParam) of type = \(type(of: tempParam))")
                        print("tempParam[response] = \(tempParam["response"]!)")

                        if tempParam["response"] as! String == "ERROR" {
                            print("Error Response from the server with message:\n", tempParam["message"]!)
                        }
                        else {
                            e_hex = tempParam["e_hex"] as? String
                            N_hex = tempParam["N_hex"] as? String

                            e = int_from_hex(hexString: e_hex!)
                            N = int_from_hex(hexString: N_hex!)

                            print("\nGET PARAMETERS\n")
                            print("e_hex = \(hex_from_int(intVal: e!)) of type = \(type(of: e_hex!))")
                            print("N_hex = \(hex_from_int(intVal: N!)) of type = \(type(of: N_hex!))")
                            print("\n")
                            print("e = \(e!) of type = \(type(of: e!))")
                            print("N = \(N!) of type = \(type(of: N!))")


                            receiveParamCheck = true

                            getParametersTime = Date().timeIntervalSince(paramStartTime)
                        }
                    }
                    
                    
                    
                }.padding(.all).font(.title)
                
                if receiveParamCheck {
                    VStack {
                        Text("N_hex = " + N_hex!)
                                    .padding(.vertical)
                        Text("e_hex = " + e_hex!)
                            .padding(.vertical)
                        Text("N = " + String(N!))
                                    .padding(.vertical)
                        Text("e = " + String(e!))
                            .padding(.vertical)
                        Text("Runtime = " + String(getParametersTime)).font(.subheadline).foregroundColor(Color.purple).multilineTextAlignment(.leading).padding(/*@START_MENU_TOKEN@*/.all/*@END_MENU_TOKEN@*/)
                        
                    }
                }
            }
            //MARK: Preparation for sending request to generating blind user secret key
            if receiveParamCheck {
                VStack{
                    Text("Request Secret Key").font(.largeTitle).multilineTextAlignment(.center).padding(.all)
                    
                    HStack {
                        // Get user ID
                        TextField("Enter your String ID", text: $nameTextField)
                            .onAppear {
                                self.nameTextField = "Raadhesh98"
                            }
                        
                        Button("Confirm Name") {
                            let extractStartTime = Date()
                            
                            let inputID = nameTextField
                            let user = userClient(stringID: inputID, N_hex: N_hex!, e_hex: e_hex!)
                            currentUserDict = user.saveDict
                            print("requestDict = \n\(user.requestDict)\n")
                            
                            //Assign N,e,N_hex,e_hex,r,r_hex,stringID,hashID,blindID
                            N = user.N
                            e = user.e
                            N_hex = user.N_hex
                            e_hex = user.e_hex
                            r = user.r
                            r_hex = user.r_hex
                            stringID = user.stringID
                            hashID = user.hashID
                            blindID=user.blindID
                            
                            if blindID == ""{
                                print("\n\nERROR: blindID is nil\n\n")
                            }
                            else{
                                
                                //MARK: Debugging int base of hashID
                                print("\nPrep for Requesting Blind Secret Key\n")
                                print("hashID = ", hashID)
                                let intHashID = int_from_hex(hexString: hashID)
                                print("hashID (int) = ", intHashID)
                                
                                print("blindID = ", blindID)
                                let intblindID = int_from_hex(hexString: blindID)
                                print("blindID (int) = ", intblindID)
                                print("\n\n")
                                
                                extractPrepCheck = true
                                extractPrepTime = Date().timeIntervalSince(extractStartTime)
                            }
                            
                            
                        }.padding()
                    }
                    VStack {
                        if extractPrepCheck{
                            VStack{
                                Text("Hash Name = " + hashID).padding(.all)
                                Text("Random Value (hex format) = " + r_hex!).padding(.all)
                                Text("Blinded Name = " + blindID).padding(.all)
                                Text("Runtime = " + String(extractPrepTime)).font(.subheadline).foregroundColor(Color.purple).multilineTextAlignment(.leading).padding(/*@START_MENU_TOKEN@*/.all/*@END_MENU_TOKEN@*/)
                            }
                            
                        }
                    }
                    // MARK: Request Blind Secret Key
                    VStack {
                        if extractPrepCheck{
                            Button("Request Blind Secret Key") {
                                let bsk_StartTime = Date()
                                
                                let user = userClient(stringID: stringID, r_hex: r_hex!, N_hex: N_hex!, e_hex: e_hex!)
                                
                                // if requestSecretJSON is not nil then we send request to server
                                if let requestSecretJSON = dictionaryToJsonString(dictionary: user.requestDict) {
                                    ws.socket.write(string: requestSecretJSON)
                                    
                                    
                                    DispatchQueue.main.asyncAfter(deadline: .now() + seconds) {
                                        // Put your code which should be executed with a delay here
                                        let tempParam = jsonStringToDictionary(jsonString: ws.receivedMessage)!
                                        print("Received JSON String = \(tempParam) of type = \(type(of: tempParam))\n")
                                        
                                        if tempParam["response"] as! String == "ERROR" {
                                            print("Error Response from the server with message:\n", tempParam["message"]!)
                                        }
                                        else {
                                            blindSigma = tempParam["secretKey"] as! String
                                            print("Blind Secret Key = ", blindSigma)
                                            getBlindSecretKeyTime = Date().timeIntervalSince(bsk_StartTime)
                                            let sigmaStartTime = Date()
                                            let user1 = userClient(stringID: stringID, blindSigma: blindSigma, r_hex: r_hex!, N_hex: N_hex!, e_hex: e_hex!)
                                            sigma = user1.sigma!
                                            print("Unblinded Secret Key = ", sigma)
                                            print("\n\n")

                                            extractPostCheck = true
                                            getUnBlindSecretKeyTime = Date().timeIntervalSince(sigmaStartTime)
                                        }
                                    }
                                }
                                
                                
                            }.padding(.all).font(.title)
                            
                            if extractPostCheck {
                                VStack {
                                    Text("Blind Sigma = " + blindSigma).padding(.all)
                                    Text("Sigma = " + sigma).padding(.all)
                                    Text("Runtime = " + String(getBlindSecretKeyTime)).font(.subheadline).foregroundColor(Color.purple).multilineTextAlignment(.leading).padding(/*@START_MENU_TOKEN@*/.all/*@END_MENU_TOKEN@*/)
                                    Text("Runtime = " + String(getUnBlindSecretKeyTime)).font(.subheadline).foregroundColor(Color.purple).multilineTextAlignment(.leading).padding(/*@START_MENU_TOKEN@*/.all/*@END_MENU_TOKEN@*/)
                                }
                            }
                            
                        }
                    }
                }
            }
            //MARK: Identification Part
            if extractPostCheck {
                Button("Request Identification") {
                    let identificationStartTime = Date()
                    
                    let user = userClient(stringID: stringID, blindSigma: blindSigma, r_hex: r_hex!, N_hex: N_hex!, e_hex: e_hex!)
                    //MARK: CMT
                    y = user.y
                    Y = user.Y
                    
                    let requestDict = user.requestDict
                    let requestJSON = dictionaryToJsonString(dictionary: requestDict)!

                    ws.socket.write(string: requestJSON)
                    
                    // Alternate Request JSON that contains all information known to iOS client
//                    let altRequestJSON = user.alternateRequestString!
//                    ws.socket.write(string: altRequestJSON)
                    
                    //MARK: CHL
                    DispatchQueue.main.asyncAfter(deadline: .now() + seconds) {
                        let responseJSONString = ws.receivedMessage
                        let responseDict = jsonStringToDictionary(jsonString: responseJSONString)!
                        
                        // Check if error from the server
                        if responseDict["response"] as! String == "ERROR" {
                            print("\n\n")
                            print("Server ERROR: ", responseDict["message"]!)
                            print("\n\n")
                            
                        }
                        else{
                            CHL = responseDict["CHL"] as? String
                            c = int_from_hex(hexString: CHL!)
                            print("\n\nReceived CHL = ", CHL!)
                            print("CHL(int format) = c = \n", c!)
                            
                            z = genRSP_Val(c: c!, y: y!, N: N!, secretKey: user.blindSigma!)
                            print("\nz = ", z!)
                            let RSP_Dict = genRSP_Dict(z: z!)
                            print("z (hex format) = RSP = \n", RSP_Dict["RSP"]!)
                            let RSP_JSON = dictionaryToJsonString(dictionary: RSP_Dict)!
                            print("\nRESPONSE JSON sent to Server =\n", RSP_JSON)
                            ws.socket.write(string: RSP_JSON)
                            
                            //MARK: RSP
                            
                            DispatchQueue.main.asyncAfter(deadline: .now() + seconds) {
                                let verificationJSONString = ws.receivedMessage
                                let verificationDict = jsonStringToDictionary(jsonString: verificationJSONString)!
                                print("Server Final Response =\n", verificationDict)
                                
                                if verificationDict["response"] as! String == "ERROR" {
                                    print("Error from Server: ", verificationDict["message"]!)
                                }
                                else {
                                    print("\nServer Response Message =\n", verificationDict["message"]!)
                                    
                                    identitySuccess = verificationDict["identityCheck"] as? Bool
                                    identificationCheck = true
                                    
                                    blindIdentificationTime = Date().timeIntervalSince(identificationStartTime)
                                    ws.socket.disconnect()
                                    
                                    totalTimeTaken = Date().timeIntervalSince(totalStartTime)
                                    //MARK: Runtimes
                                    print("\n\n\n")
                                    print("Runtimes in seconds\n")
                                    print("Get Parameters = ", getParametersTime)
                                    print("Prep Time for Requesting Blind Secret Key = ", extractPrepTime)
                                    print("Get Blind Secret Key = ", getBlindSecretKeyTime)
                                    print("Get Unblinded Secret Key = ", getUnBlindSecretKeyTime)
                                    print("Blind User Identification Time = ", blindIdentificationTime)
                                    
                                    print("\n")
                                    // processOnlyTime is to know the time taken without considering the time taken for user to press buttons
                                    let processOnlyTime = getParametersTime + extractPrepTime + getBlindSecretKeyTime + getBlindSecretKeyTime + blindIdentificationTime
                                    print("Time taken only without considering user = ", processOnlyTime)
                                    print("Total Time Taken = ", totalTimeTaken)
                                    print("\n\n\n")
                                    
                                    if !identitySuccess! {
                                        print("\n\nShow all parameter values,\n")
                                        print("N = ", user.N)
                                        print("e = ", user.e)
                                        print("stringID = ", user.stringID)
                                        print("hashID = ", user.hashID)
                                        print("r = ", user.r)
                                        print("blindID = ", user.blindID)
                                        print("sigma = ", user.sigma!)
                                        print("blindSigma = ", user.blindSigma!)
                                        print("y = ", user.y!)
                                        print("Y = ", user.Y!)
                                    }
                                }
                                
                            }
                        }
                    }
                    
                    
                }.font(.title).multilineTextAlignment(.center).padding(.all)
                
                if identificationCheck{
                    if identitySuccess ?? false {
                        VStack {
                            Text("IDENTIFICATION SUCCESSFULL \n:)").padding(.all).font(.largeTitle).multilineTextAlignment(.center)
                            Text("Runtime = " + String(blindIdentificationTime)).font(.subheadline).foregroundColor(Color.purple).multilineTextAlignment(.leading).padding(/*@START_MENU_TOKEN@*/.all/*@END_MENU_TOKEN@*/)
                            
                        }
                    }
                    if !(identitySuccess ?? true) {
                        VStack {
                            Text("IDENTIFICATION UNSUCCESSFULL \n:(").padding(.all).font(.largeTitle).multilineTextAlignment(.center)
                            Text("Runtime = " + String(blindIdentificationTime)).font(.subheadline).foregroundColor(Color.purple).multilineTextAlignment(.leading).padding(/*@START_MENU_TOKEN@*/.all/*@END_MENU_TOKEN@*/)
                        }
                    }
                }
            }
            
            
        }
        .padding().frame(width: screenWidth)
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
