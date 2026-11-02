import Foundation
import Network
import SwiftUI

private struct Offer: Decodable, Sendable {
    let serverIPv4: [UInt8]
    let serverPort: UInt16
    let serverName: String
    let alpn: String
    let token: String
    let scenario: String
}

private struct NativeResult: Codable, Sendable {
    let scenario: String
    let token: String
    let streamID: UInt64
    let boundPortBefore: UInt16
    let boundPortAfter: UInt16
    let nativeCalls: [String]
}

private struct ProbeFailure: Error {
    let reason: String
}

private enum NativeProbe {
    static func run(offer: Offer, certificate: Data,
                    progress: @escaping @Sendable (String) -> Void) throws -> NativeResult {
        guard offer.serverIPv4.count == 4, offer.serverPort != 0,
              offer.scenario == "controlled-nat-port-change" else {
            throw ProbeFailure(reason: "Invalid probe offer")
        }
        var config = quicz_mobile_client_config()
        config.server_ipv4 = (offer.serverIPv4[0], offer.serverIPv4[1], offer.serverIPv4[2], offer.serverIPv4[3])
        config.server_port = offer.serverPort
        config.allow_migration = 1
        let name = Data(offer.serverName.utf8)
        let alpn = Data(offer.alpn.utf8)
        var owner: OpaquePointer?
        var calls: [String] = []
        progress("Creating the native client")
        calls.append("create")
        let created = certificate.withUnsafeBytes { ca in
            name.withUnsafeBytes { name in
                alpn.withUnsafeBytes { alpn in
                    config.ca_certificate_der = ca.bindMemory(to: UInt8.self).baseAddress
                    config.ca_certificate_der_length = ca.count
                    config.server_name = name.bindMemory(to: UInt8.self).baseAddress
                    config.server_name_length = name.count
                    config.alpn = alpn.bindMemory(to: UInt8.self).baseAddress
                    config.alpn_length = alpn.count
                    return quicz_mobile_client_create(&config, &owner)
                }
            }
        }
        try check(created, "create")
        guard let client = owner else { throw ProbeFailure(reason: "Missing native client") }
        defer {
            progress("Closing the native client")
            quicz_mobile_client_close(client)
            quicz_mobile_client_destroy(client)
        }
        var before = quicz_mobile_ipv4_endpoint()
        try check(quicz_mobile_client_bound_ipv4(client, &before), "bound port")
        try check(quicz_mobile_client_set_keepalive_interval(client, 0), "keepalive")
        progress("Connecting with certificate verification")
        calls.append("connect")
        try check(quicz_mobile_client_connect_timeout(client, 6_000), "connect")
        var stream: UInt64 = 0
        calls.append("open")
        try check(quicz_mobile_client_open_bidi(client, &stream), "open stream")

        func send(_ phase: String) throws {
            let payload = Data("\(offer.token):\(phase)".utf8)
            let result = payload.withUnsafeBytes { bytes in
                quicz_mobile_client_send(client, stream, bytes.bindMemory(to: UInt8.self).baseAddress,
                                         bytes.count, 0)
            }
            try check(result, "send \(phase)")
        }
        func receive(_ phase: String) throws {
            let expected = Data("\(offer.token):\(phase)".utf8)
            var response = Data()
            while response.count < expected.count {
                var bytes = [UInt8](repeating: 0, count: expected.count - response.count)
                var count = 0
                let result = bytes.withUnsafeMutableBufferPointer { buffer in
                    quicz_mobile_client_receive(client, stream, buffer.baseAddress, buffer.count, &count)
                }
                try check(result, "receive \(phase)")
                guard count > 0, count <= bytes.count else { throw ProbeFailure(reason: "Unexpected stream EOF") }
                response.append(contentsOf: bytes.prefix(count))
            }
            guard response == expected else { throw ProbeFailure(reason: "Payload mismatch: \(phase)") }
        }
        progress("Checking the original path")
        try send("ready")
        try receive("control")
        // The Host changes only the proxy port during this quiet interval.
        Thread.sleep(forTimeInterval: 2)
        progress("Checking the same stream after NAT rebinding")
        try send("rebind")
        try receive("host-push")
        try send("after")
        try receive("done")
        var after = quicz_mobile_ipv4_endpoint()
        try check(quicz_mobile_client_bound_ipv4(client, &after), "final bound port")
        guard before.port == after.port, calls == ["create", "connect", "open"] else {
            throw ProbeFailure(reason: "Native owner was replaced")
        }
        try send("finish")
        return NativeResult(scenario: offer.scenario, token: offer.token, streamID: stream,
                            boundPortBefore: before.port, boundPortAfter: after.port, nativeCalls: calls)
    }

    private static func check(_ status: Int32, _ operation: String) throws {
        guard status == 0 else { throw ProbeFailure(reason: "\(operation) returned native status \(status)") }
    }
}

@MainActor
private final class ProbeModel: ObservableObject {
    @Published var stage = "Preparing" {
        didSet { try? save(["stage": stage, "interface": pathDescription], filename: "stage.json") }
    }
    @Published var pathDescription = "Waiting for the interface snapshot"
    private let monitor = NWPathMonitor()
    private var permission: NWConnection?
    private var started = false
    private var finished = false

    func start() {
        guard !started else { return }
        started = true
        monitor.pathUpdateHandler = { [weak self] path in
            let description = "status=\(path.status) Wi-Fi=\(path.usesInterfaceType(.wifi)) cellular=\(path.usesInterfaceType(.cellular))"
            Task { @MainActor in self?.pathDescription = description }
        }
        monitor.start(queue: DispatchQueue(label: "probe.path"))
        do {
            let offer = try JSONDecoder().decode(Offer.self, from: Data(contentsOf: Bundle.main.url(forResource: "offer", withExtension: "json")!))
            let certificate = try Data(contentsOf: Bundle.main.url(forResource: "server", withExtension: "der")!)
            stage = "Allow local network access if iOS asks"
            let host = offer.serverIPv4.map(String.init).joined(separator: ".")
            let connection = NWConnection(host: .init(host), port: .init(rawValue: offer.serverPort)!, using: .udp)
            permission = connection
            connection.stateUpdateHandler = { [weak self] state in
                if case .waiting(let error) = state {
                    Task { @MainActor [weak self] in self?.stage = "Waiting for LAN: \(error)" }
                }
                if case .failed(let error) = state {
                    Task { @MainActor [weak self] in self?.fail("LAN check: \(error)") }
                }
                guard case .ready = state else { return }
                connection.send(content: Data("MVP_PERMISSION_CHECK".utf8), completion: .contentProcessed { _ in })
                connection.receiveMessage { bytes, _, _, error in
                    Task { @MainActor [weak self] in
                        guard let self else { return }
                        guard self.permission != nil else { return }
                        self.permission = nil
                        connection.stateUpdateHandler = nil
                        connection.cancel()
                        if let error { self.fail(String(describing: error)); return }
                        guard bytes == Data("MVP_PERMISSION_READY".utf8) else { self.fail("LAN permission check failed"); return }
                        self.run(offer: offer, certificate: certificate)
                    }
                }
            }
            connection.start(queue: DispatchQueue(label: "probe.permission"))
        } catch { fail(String(describing: error)) }
    }

    private func run(offer: Offer, certificate: Data) {
        Task {
            do {
                let progress: @Sendable (String) -> Void = { [self] stage in
                    Task { @MainActor in
                        if !self.finished { self.stage = stage }
                    }
                }
                let result = try await Task.detached(priority: .userInitiated) {
                    try NativeProbe.run(offer: offer, certificate: certificate, progress: progress)
                }.value
                let encoded = try JSONEncoder().encode(result)
                let report = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
                let source = try String(contentsOf: Bundle.main.url(forResource: "client-source", withExtension: "txt")!, encoding: .utf8)
                try save(["verdict": "passed", "result": report, "interface": pathDescription, "clientSource": source.trimmingCharacters(in: .whitespacesAndNewlines)])
                finished = true
                stage = "Passed: same native client, port and stream"
            } catch { fail(String(describing: error)) }
        }
    }

    private func fail(_ reason: String) {
        finished = true
        stage = "Failed: \(reason)"
        try? save(["verdict": "failed", "reason": reason, "interface": pathDescription])
    }

    private func save(_ report: [String: Any], filename: String = "result.json") throws {
        let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent(filename)
        try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys, .prettyPrinted]).write(to: url, options: .atomic)
    }
}

@main
struct NATProbeApp: App {
    @StateObject private var model = ProbeModel()
    var body: some Scene {
        WindowGroup {
            NavigationStack {
                Form {
                    Section("Controlled NAT port change") {
                        Text(model.stage)
                        Text("This test keeps Wi-Fi and cellular settings unchanged.")
                            .foregroundStyle(.secondary)
                    }
                    Section("Observed interface") {
                        Text(model.pathDescription).font(.body.monospaced())
                    }
                }
                .navigationTitle("NAT Probe")
                .task { model.start() }
            }
        }
    }
}
