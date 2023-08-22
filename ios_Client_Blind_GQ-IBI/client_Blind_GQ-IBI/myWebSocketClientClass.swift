//
//  myWebSocketClientClass.swift
//  client_Blind_GQ-IBI
//
//  Created by Raadhesh Kannan on 18/08/2023.
//

import Foundation
import Starscream


// MARK: webSocketManager class is for connecting to Server.
class webSocketManager: ObservableObject, WebSocketDelegate {
    var socket: WebSocket!
    var isConnected = false
    let server = WebSocketServer()
    
    @Published var urlString = "http://localhost:8765"
    
    //Could try using ? and default val !!!!!!
    @Published var receivedMessage: String = "Error: No Message Received"
//    @Published var dictMessage = [String:Any]()
    
    // MARK: During class initialization, the iOS client (us) connects to server
    init() {
        var request = URLRequest(url: URL(string: urlString)!)
        request.timeoutInterval = 5
        socket = WebSocket(request: request)
        socket.delegate = self
        socket.connect()
    }
    init(givenStringURL: String) {
        urlString = givenStringURL
        var request = URLRequest(url: URL(string: urlString)!)
        request.timeoutInterval = 5
        socket = WebSocket(request: request)
        socket.delegate = self
        socket.connect()
    }
    
    // starsscream library uses didReceive function where when Starscream.WebSocketEvent changes in value then the following operation takes place
    func didReceive(event: Starscream.WebSocketEvent, client: Starscream.WebSocket) {
        switch event {
        case .connected(let headers):
            isConnected = true
            print("websocket is connected: \(headers)")
        case .disconnected(let reason, let code):
            isConnected = false
            print("websocket is disconnected: \(reason) with code: \(code)")
        case .text(let string):
            print("Received text: \(string)")
            receivedMessage = string
        case .binary(let data):
            print("Received data: \(data.count)")
        case .ping(_):
            break
        case .pong(_):
            break
        case .viabilityChanged(_):
            break
        case .reconnectSuggested(_):
            break
        case .cancelled:
            isConnected = false
        case .error(let error):
            isConnected = false
            handleError(error)
        }
    }
    // starsscream library default error function
    func handleError(_ error: Error?) {
        if let e = error as? WSError {
            print("websocket encountered an error: \(e.message)")
        } else if let e = error {
            print("websocket encountered an error: \(e.localizedDescription)")
        } else {
            print("websocket encountered an error")
        }
    }
}
