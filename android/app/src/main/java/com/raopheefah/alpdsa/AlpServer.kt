package com.raopheefah.alpdsa

import android.content.Context
import java.net.ServerSocket
import java.net.Socket
import java.io.DataInputStream
import java.io.DataOutputStream
import kotlin.concurrent.thread

object AlpServer {
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var running = false

    @Volatile
    var setupModeEnabled = false
        private set

    // Guards all KeyManager/Keystore access from concurrent client threads
    private val keystoreLock = Any()

    private const val CMD_GET_PUBKEY: Byte = 0x01
    private const val CMD_AUTH: Byte = 0x02

    fun isRunning(): Boolean = running

    fun start(context: Context) {
        if (running) return
        val port = KeyManager.getPort(context)
        running = true
        thread {
            try {
                serverSocket = ServerSocket(port)
                while (running) {
                    val client = try {
                        serverSocket?.accept()
                    } catch (_: Exception) {
                        // socket closed via stop() -> exit loop quietly
                        null
                    } ?: break
                    thread { handleClient(context, client) }
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    private fun handleClient(context: Context, client: Socket) {
        try {
            client.soTimeout = 3000 // avoid a stuck client hanging a thread forever

            val input = DataInputStream(client.getInputStream())
            val output = DataOutputStream(client.getOutputStream())

            val cmd = input.readByte()

            val alias = synchronized(keystoreLock) {
                KeyManager.getActiveAlias(context)
            }

            if (alias == null) {
                output.writeInt(-1)
                output.flush()
                return
            }

            when (cmd) {
                CMD_GET_PUBKEY -> {
                    if (!setupModeEnabled) {
                        output.writeInt(-1)
                        output.flush()
                        return
                    }
                    val pubKeyBytes = synchronized(keystoreLock) {
                        KeyManager.getPublicKeyBytes(alias)
                    }
                    output.writeInt(pubKeyBytes.size)
                    output.write(pubKeyBytes)
                    output.flush()
                }

                CMD_AUTH -> {
                    val nonceLen = input.readInt()
                    if (nonceLen !in 1..4096) {
                        output.writeInt(-1)
                        output.flush()
                        return
                    }
                    val nonce = ByteArray(nonceLen)
                    input.readFully(nonce)

                    val signature = synchronized(keystoreLock) {
                        val sig = KeyManager.sign(alias, nonce)
                        KeyManager.incrementAuthCount(context)
                        sig
                    }
                    output.writeInt(signature.size)
                    output.write(signature)
                    output.flush()
                }

                else -> {
                    output.writeInt(-1)
                    output.flush()
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {
            client.close()
        }
    }

    fun setSetupMode(enabled: Boolean) {
        setupModeEnabled = enabled
    }

    fun stop() {
        running = false
        try {
            serverSocket?.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        serverSocket = null
    }
}