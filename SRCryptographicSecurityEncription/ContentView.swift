//
//  ContentView.swift
//  SRCryptographicSecurityEncription
//
//  Created by Sahan Ravindu on 04/03/2024.
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("Hello, world!")
        }
        .padding()
        .onAppear(perform: {
            encryptDecrypt()
        })
    }
    
    private func encryptDecrypt() {
        let facade = KeychainFacade()
        
        let text = "Super secret text"
        
        do {
            if let encryptedData = try facade.encrypt(text: text) {
                print("Text encryption successful : <-- \(encryptedData) -->")
                
                if let decryptedData = try facade.decrypt(data: encryptedData) {
                    print("Data decrypted successfully")
                    print(String(data: decryptedData, encoding: .utf8) ?? "")
                }
            }
        } catch {
            print(error)
        }
    }
}

#Preview {
    ContentView()
}
