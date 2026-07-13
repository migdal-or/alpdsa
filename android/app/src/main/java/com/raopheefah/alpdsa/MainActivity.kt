package com.raopheefah.alpdsa

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.raopheefah.alpdsa.ui.theme.AlpDSATheme
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.seconds

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AlpDSATheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    MainScreen(modifier = Modifier.padding(innerPadding))
                }
            }
        }
    }

    // NOTE: intentionally no AlpServer.stop() here anymore.
    // The server's lifecycle is now owned by AlpForegroundService, so closing
    // this Activity (e.g. switching apps) must NOT stop the background auth server.
}

@Composable
fun MainScreen(modifier: Modifier = Modifier) {
    val context = androidx.compose.ui.platform.LocalContext.current

    val keyAliases = remember { mutableStateOf(KeyManager.listKeyAliases(context)) }
    val activeAlias = remember { mutableStateOf(KeyManager.getActiveAlias(context)) }
    val newKeyName = remember { mutableStateOf("") }

    val port = remember { mutableStateOf(KeyManager.getPort(context).toString()) }

    val serverRunning = remember { mutableStateOf(AlpServer.isRunning()) }
    val setupMode = remember { mutableStateOf(AlpServer.setupModeEnabled) }
    val authCount = remember { mutableIntStateOf(KeyManager.getAuthCount(context)) }
    // Poll the auth counter and real server state periodically, so the UI stays
    // correct even if it was recreated while the foreground service kept running.
    LaunchedEffect(Unit) {
        while (true) {
            authCount.intValue = KeyManager.getAuthCount(context)
            serverRunning.value = AlpServer.isRunning()
            delay(1.5.seconds)
        }
    }

    fun refreshKeys() {
        keyAliases.value = KeyManager.listKeyAliases(context)
        activeAlias.value = KeyManager.getActiveAlias(context)
    }

    Column(modifier = modifier.padding(16.dp)) {
        Text(text = "Keys")

        LazyColumn {
            items(keyAliases.value) { alias ->
                Row {
                    RadioButton(
                        selected = (alias == activeAlias.value),
                        onClick = {
                            KeyManager.setActiveAlias(context, alias)
                            refreshKeys()
                        }
                    )
                    Text(text = alias, modifier = Modifier.padding(top = 12.dp))
                    Button(onClick = {
                        KeyManager.deleteKey(context, alias)
                        refreshKeys()
                    }) {
                        Text("Delete")
                    }
                }
            }
        }

        OutlinedTextField(
            value = newKeyName.value,
            onValueChange = { newKeyName.value = it },
            label = { Text("New key name") }
        )
        Button(onClick = {
            if (newKeyName.value.isNotBlank()) {
                KeyManager.createKey(context, newKeyName.value)
                newKeyName.value = ""
                refreshKeys()
            }
        }) {
            Text("Create key")
        }

        Text(text = "Port setup")

        OutlinedTextField(
            value = port.value,
            onValueChange = { port.value = it },
            label = { Text("Server port") }
        )
        Button(onClick = {
            port.value.toIntOrNull()?.let { KeyManager.setPort(context, it) }
        }) {
            Text("Save port")
        }

        Text(text = "Server")

        Button(onClick = {
            if (serverRunning.value) {
                AlpForegroundService.stop(context)
                serverRunning.value = false
            } else {
                AlpForegroundService.start(context)
                serverRunning.value = true
            }
        }) {
            Text(text = if (serverRunning.value) "Stop Server" else "Start Server")
        }

        Button(onClick = {
            setupMode.value = !setupMode.value
            AlpServer.setSetupMode(setupMode.value)
        }) {
            Text(text = if (setupMode.value) "Disable Setup Mode" else "Enable Setup Mode")
        }

        if (activeAlias.value != null) {
            Text(text = "Active key: ${activeAlias.value}")
        } else {
            Text(text = "No active key, create one")
        }

        Text(text = "Auth requests served: ${authCount.intValue}")
    }
}