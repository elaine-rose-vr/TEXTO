// MainActivity.kt — TEXTO V-3.3 | Bottom Status, FAB Dock, Custom Timers, OOM Crash Fix
// CDP: Full replacement — Zero placeholders.

package com.example.texto

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.IBinder
import android.util.Base64
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import coil.compose.AsyncImage
import com.canhub.cropper.CropImageContract
import com.canhub.cropper.CropImageContractOptions
import com.canhub.cropper.CropImageOptions
import com.google.android.gms.auth.api.phone.SmsRetriever
import com.google.firebase.FirebaseApp
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.PhoneAuthCredential
import com.google.firebase.auth.PhoneAuthOptions
import com.google.firebase.auth.PhoneAuthProvider
import com.google.firebase.database.*
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// ─────────────────────────────────────────────────────────────────────────────
// PALETTE
// ─────────────────────────────────────────────────────────────────────────────
object Palette {
    val Bg        = Color(0xFF0A0E14)
    val Surface   = Color(0xFF141922)
    val Surface2  = Color(0xFF1C2433)
    val Accent    = Color(0xFF00C896)
    val AccentDim = Color(0x3300C896)
    val Muted     = Color(0xFF8899AA)
    val White     = Color.White
    val Error     = Color(0xFFFF5370)
    val BubbleOut = Color(0xFF00C896)
    val BubbleIn  = Color(0xFF1C2433)
}

fun String.sanitise(): String = replace("+", "").replace(" ", "").trim()
fun buildRoomId(a: String, b: String): String = listOf(a.sanitise(), b.sanitise()).sorted().joinToString("_")

// ─────────────────────────────────────────────────────────────────────────────
// SIGNAL PROTOCOL ENGINES
// ─────────────────────────────────────────────────────────────────────────────
object SignalKeyManager {
    private const val KEY_ALIAS         = "texto_identity_key_v1"
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val EC_CURVE          = "secp256r1"

    fun getOrCreateIdentityKeyPair(): Boolean {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (ks.containsAlias(KEY_ALIAS)) return false
        val purposes = if (Build.VERSION.SDK_INT >= 31)
            android.security.keystore.KeyProperties.PURPOSE_SIGN or android.security.keystore.KeyProperties.PURPOSE_AGREE_KEY
        else
            android.security.keystore.KeyProperties.PURPOSE_SIGN
        val spec = android.security.keystore.KeyGenParameterSpec.Builder(KEY_ALIAS, purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
            .setDigests(android.security.keystore.KeyProperties.DIGEST_SHA256, android.security.keystore.KeyProperties.DIGEST_SHA512)
            .build()
        KeyPairGenerator.getInstance(android.security.keystore.KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
            .apply { initialize(spec); generateKeyPair() }
        return true
    }

    fun getPublicKeyBase64(): String? = try {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val cert = ks.getCertificate(KEY_ALIAS) ?: return null
        Base64.encodeToString(cert.publicKey.encoded, Base64.NO_WRAP)
    } catch (e: Exception) { null }

    fun getPrivateKey(): java.security.PrivateKey? = try {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        ks.getKey(KEY_ALIAS, null) as? java.security.PrivateKey
    } catch (e: Exception) { null }
}

object SignalHandshakeManager {
    fun reconstructPublicKey(base64: String): java.security.PublicKey? = try {
        val bytes = Base64.decode(base64, Base64.DEFAULT)
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(bytes))
    } catch (e: Exception) { null }

    fun deriveAesKey(myPrivateKey: java.security.PrivateKey, peerPublicKey: java.security.PublicKey): SecretKeySpec? = try {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(myPrivateKey); ka.doPhase(peerPublicKey, true)
        SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(ka.generateSecret()), "AES")
    } catch (e: Exception) { null }
}

object SignalCryptoEngine {
    private const val GCM_IV_LENGTH  = 12
    private const val GCM_TAG_LENGTH = 128

    fun encrypt(plainText: String, aesKey: SecretKeySpec): String = try {
        val iv = ByteArray(GCM_IV_LENGTH).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))
        Base64.encodeToString(iv + cipher.doFinal(plainText.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
    } catch (e: Exception) { "" }

    fun decrypt(base64CipherText: String, aesKey: SecretKeySpec): String {
        return try {
            val combined = Base64.decode(base64CipherText, Base64.DEFAULT)
            if (combined.size < GCM_IV_LENGTH) return "🔒 [Corrupted Message]"
            val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
            val cipherText = combined.copyOfRange(GCM_IV_LENGTH, combined.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))
            String(cipher.doFinal(cipherText), Charsets.UTF_8)
        } catch (e: Exception) { "🔒 [Decryption Failed]" }
    }
}

object KeyRegistry {
    fun publishPublicKey(phone: String, onResult: (Boolean) -> Unit) {
        val pubKey = SignalKeyManager.getPublicKeyBase64() ?: return onResult(false)
        FirebaseDatabase.getInstance().reference.child("public_keys").child(phone.sanitise())
            .setValue(mapOf("publicKey" to pubKey, "registeredAt" to System.currentTimeMillis()))
            .addOnSuccessListener { onResult(true) }.addOnFailureListener { onResult(false) }
    }

    fun fetchPeerPublicKey(peerPhone: String, onResult: (String?) -> Unit) {
        FirebaseDatabase.getInstance().reference.child("public_keys").child(peerPhone.sanitise()).child("publicKey")
            .get().addOnSuccessListener { onResult(it.getValue(String::class.java)) }.addOnFailureListener { onResult(null) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DATA MODELS
// ─────────────────────────────────────────────────────────────────────────────
data class Contact(val phone: String = "", val name: String = "", val addedAt: Long = 0L)
data class RecentChat(val phone: String = "", val lastMsg: String = "", val timestamp: Long = 0L, val unread: Int = 0)
enum class MsgType { TEXT, IMAGE, VIDEO, AUDIO, VOICE, DOCUMENT }
data class ChatMessage(val id: String = "", val text: String = "", val senderId: String = "", val timestamp: Long = 0L, val status: String = "sending", val type: String = "TEXT", val fileName: String = "", val fileSize: Long = 0L, val mimeType: String = "")
data class UserStatus(val text: String = "", val base64Image: String? = null, val timestamp: Long = 0L, val expiresAt: Long = 0L)

sealed class Screen {
    object Splash : Screen()
    object Auth : Screen()
    data class Vault(val phone: String, val pubKey: String) : Screen()
    data class Contacts(val myPhone: String) : Screen()
    data class Chat(val myPhone: String, val peerPhone: String, val peerName: String) : Screen()
    data class Settings(val myPhone: String) : Screen()
}

sealed class AuthState {
    object Idle : AuthState()
    object SendingOtp : AuthState()
    data class AwaitingCode(val verificationId: String) : AuthState()
    object VerifyingOtp : AuthState()
    object GeneratingKey : AuthState()
    object PublishingKey : AuthState()
    data class Done(val phone: String, val pubKey: String) : AuthState()
    data class AuthError(val message: String) : AuthState()
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN ACTIVITY
// ─────────────────────────────────────────────────────────────────────────────
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        FirebaseApp.initializeApp(this)

        val serviceIntent = Intent(this, TextoZombieService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent)
        } else {
            startService(serviceIntent)
        }

        enableEdgeToEdge()
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    background = Palette.Bg, surface = Palette.Surface,
                    primary = Palette.Accent, onPrimary = Color.Black,
                    onSurface = Palette.White, onBackground = Palette.White
                )
            ) { TextoApp() }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ROOT COMPOSABLE
// ─────────────────────────────────────────────────────────────────────────────
@Composable
fun TextoApp() {
    var screen by remember { mutableStateOf<Screen>(Screen.Splash) }
    val context = LocalContext.current

    var toastMessage by remember { mutableStateOf<String?>(null) }
    var toastVisible by remember { mutableStateOf(false) }

    val showInAppToast: (String) -> Unit = { msg ->
        toastMessage = msg
        toastVisible = true
        Handler(Looper.getMainLooper()).postDelayed({ toastVisible = false }, 3500)
    }

    LaunchedEffect(Unit) {
        val user = FirebaseAuth.getInstance().currentUser
        screen = if (user != null) {
            val phone = user.phoneNumber ?: ""
            SignalKeyManager.getOrCreateIdentityKeyPair()
            val pubKey = SignalKeyManager.getPublicKeyBase64() ?: ""
            if (pubKey.isNotEmpty()) KeyRegistry.publishPublicKey(phone) {}
            Screen.Contacts(phone)
        } else { Screen.Auth }
    }

    Box(Modifier.fillMaxSize()) {
        AnimatedContent(
            targetState = screen,
            transitionSpec = { (fadeIn(tween(280)) + slideInHorizontally(tween(280)) { it }) togetherWith (fadeOut(tween(200)) + slideOutHorizontally(tween(200)) { -it }) },
            label = "nav"
        ) { s ->
            when (s) {
                is Screen.Splash   -> SplashScreen()
                is Screen.Auth     -> AuthScreen(onAuthenticated = { phone, pubKey -> screen = Screen.Vault(phone, pubKey) })
                is Screen.Vault    -> VaultScreen(phone = s.phone, pubKey = s.pubKey, onOpenInbox = { screen = Screen.Contacts(s.phone) })
                is Screen.Contacts -> ContactsScreen(
                    myPhone = s.myPhone,
                    onOpenChat = { peer, name -> screen = Screen.Chat(s.myPhone, peer, name) },
                    onOpenSettings = { screen = Screen.Settings(s.myPhone) },
                    onLogout = {
                        FirebaseAuth.getInstance().signOut()
                        context.startActivity(Intent(context, MainActivity::class.java).apply { flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK })
                    },
                    onInAppNotification = showInAppToast
                )
                is Screen.Chat     -> ChatScreen(myPhone = s.myPhone, peerPhone = s.peerPhone, peerName = s.peerName, onBack = { screen = Screen.Contacts(s.myPhone) })
                is Screen.Settings -> SettingsScreen(myPhone = s.myPhone, onBack = { screen = Screen.Contacts(s.myPhone) })
            }
        }

        AnimatedVisibility(
            visible = toastVisible,
            enter = slideInVertically(tween(320)) { -it } + fadeIn(tween(320)),
            exit  = slideOutVertically(tween(280)) { -it } + fadeOut(tween(280)),
            modifier = Modifier.align(Alignment.TopCenter)
        ) {
            Box(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 48.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Palette.Surface2).border(1.dp, Palette.Accent.copy(alpha = 0.4f), RoundedCornerShape(16.dp)).padding(horizontal = 16.dp, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Box(Modifier.size(36.dp).clip(CircleShape).background(Palette.AccentDim), Alignment.Center) { Text("💬", fontSize = 18.sp) }
                    Column(Modifier.weight(1f)) {
                        Text("New Message", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Palette.Accent, fontFamily = FontFamily.Monospace)
                        Text(toastMessage ?: "", fontSize = 14.sp, color = Palette.White, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    }
                    TextButton(onClick = { toastVisible = false }) { Text("✕", color = Palette.Muted, fontSize = 14.sp) }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SCREENS
// ─────────────────────────────────────────────────────────────────────────────
@Composable
fun SplashScreen() {
    Box(Modifier.fillMaxSize().background(Palette.Bg).systemBarsPadding(), Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("TEXTO", fontSize = 48.sp, fontWeight = FontWeight.Black, fontFamily = FontFamily.Monospace, color = Palette.Accent)
            CircularProgressIndicator(color = Palette.Accent, modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
        }
    }
}

@Composable
fun AuthScreen(onAuthenticated: (phone: String, pubKey: String) -> Unit) {
    val context = LocalContext.current
    val activity = context as ComponentActivity
    val auth = remember { FirebaseAuth.getInstance() }
    var phone by remember { mutableStateOf("") }
    var otpCode by remember { mutableStateOf("") }
    var state by remember { mutableStateOf<AuthState>(AuthState.Idle) }
    var profileUri by remember { mutableStateOf<Uri?>(null) }

    // Cropper Launcher
    val cropLauncher = rememberLauncherForActivityResult(CropImageContract()) { result ->
        if (result.isSuccessful) { profileUri = result.uriContent }
    }

    val pickerLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) {
            val options = CropImageOptions(imageSourceIncludeGallery = true, imageSourceIncludeCamera = false, aspectRatioX = 1, aspectRatioY = 1, fixAspectRatio = true)
            cropLauncher.launch(CropImageContractOptions(uri, options))
        }
    }

    LaunchedEffect(state) { if (state is AuthState.AwaitingCode) startSmsRetriever(context) }

    Box(Modifier.fillMaxSize().background(Palette.Bg).systemBarsPadding().padding(24.dp), Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(18.dp), modifier = Modifier.fillMaxWidth()) {
            Box(
                modifier = Modifier.size(100.dp).clip(CircleShape).background(Palette.Surface2).border(2.dp, if (profileUri != null) Palette.Accent else Palette.Muted, CircleShape).clickable { pickerLauncher.launch("image/*") },
                contentAlignment = Alignment.Center
            ) {
                if (profileUri == null) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("📷", fontSize = 28.sp)
                        Text("Add Photo", fontSize = 10.sp, color = Palette.Muted, fontWeight = FontWeight.Bold)
                    }
                } else {
                    AsyncImage(model = profileUri, contentDescription = "Profile", modifier = Modifier.fillMaxSize().clip(CircleShape), contentScale = ContentScale.Crop)
                }
            }

            Text("TEXTO", fontSize = 48.sp, fontWeight = FontWeight.Black, fontFamily = FontFamily.Monospace, color = Palette.Accent)
            Text("Zero-Knowledge Messaging", fontSize = 13.sp, color = Palette.Muted)
            Spacer(Modifier.height(4.dp))

            OutlinedTextField(value = phone, onValueChange = { phone = it }, label = { Text("Phone (+91...)", color = Palette.Muted) }, singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone), colors = textoFieldColors(), modifier = Modifier.fillMaxWidth())
            AnimatedVisibility(visible = state is AuthState.AwaitingCode) {
                OutlinedTextField(value = otpCode, onValueChange = { otpCode = it }, label = { Text("6-digit OTP", color = Palette.Muted) }, singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), colors = textoFieldColors(), modifier = Modifier.fillMaxWidth())
            }

            val busy = state is AuthState.SendingOtp || state is AuthState.VerifyingOtp || state is AuthState.GeneratingKey || state is AuthState.PublishingKey

            Button(
                onClick = {
                    when (state) {
                        is AuthState.Idle, is AuthState.AuthError -> {
                            state = AuthState.SendingOtp
                            sendOtp(phone, activity, auth,
                                onCodeSent = { vId -> state = AuthState.AwaitingCode(vId) },
                                onAutoVerified = { cred ->
                                    state = AuthState.VerifyingOtp
                                    signInAndVault(cred, phone, profileUri, context, auth, onState = { ns -> state = ns }, onDone = { p, k -> onAuthenticated(p, k) })
                                },
                                onError = { msg -> state = AuthState.AuthError(msg) })
                        }
                        is AuthState.AwaitingCode -> {
                            val vId = (state as AuthState.AwaitingCode).verificationId
                            state = AuthState.VerifyingOtp
                            signInAndVault(PhoneAuthProvider.getCredential(vId, otpCode), phone, profileUri, context, auth, onState = { ns -> state = ns }, onDone = { p, k -> onAuthenticated(p, k) })
                        }
                        else -> {}
                    }
                },
                enabled = !busy && phone.isNotBlank(), colors = ButtonDefaults.buttonColors(containerColor = Palette.Accent), modifier = Modifier.fillMaxWidth().height(54.dp).clip(RoundedCornerShape(14.dp))
            ) {
                if (busy) CircularProgressIndicator(color = Color.Black, modifier = Modifier.size(22.dp), strokeWidth = 2.5.dp)
                else Text(text = if (state is AuthState.AwaitingCode) "Verify & Secure 🔐" else "Send OTP 📲", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 16.sp)
            }
            AuthStatusCard(state)
        }
    }
}

@Composable
fun VaultScreen(phone: String, pubKey: String, onOpenInbox: () -> Unit) {
    Column(Modifier.fillMaxSize().background(Palette.Bg).systemBarsPadding().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(20.dp)) {
        Spacer(Modifier.height(48.dp))
        Box(Modifier.size(88.dp).clip(CircleShape).background(Palette.AccentDim).border(2.dp, Palette.Accent, CircleShape), Alignment.Center) { Text("🔐", fontSize = 38.sp) }
        Text("Vault Active", fontSize = 26.sp, fontWeight = FontWeight.Bold, color = Palette.White)
        Text(phone, fontSize = 14.sp, color = Palette.Muted, fontFamily = FontFamily.Monospace)
        HorizontalDivider(color = Palette.Surface2)
        Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Palette.Surface).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VaultRow("Algorithm", "EC secp256r1  (NIST P-256)")
            VaultRow("Storage", "AndroidKeyStore TEE 🔒")
            VaultRow("Published", "Firebase public_keys/ ☁️")
            HorizontalDivider(color = Palette.Surface2)
            Text("Your Public Key", fontSize = 11.sp, color = Palette.Muted)
            Text(text = pubKey.chunked(32).take(3).joinToString("\n") + "\n…", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = Palette.Accent.copy(alpha = 0.8f), lineHeight = 16.sp)
        }
        Spacer(Modifier.weight(1f))
        Button(onClick = onOpenInbox, colors = ButtonDefaults.buttonColors(containerColor = Palette.Accent), modifier = Modifier.fillMaxWidth().height(54.dp).clip(RoundedCornerShape(14.dp))) {
            Text("Open Contacts →", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        }
    }
}

@OptIn(ExperimentalFoundationApi::class, ExperimentalMaterial3Api::class)
@Composable
fun ContactsScreen(myPhone: String, onOpenChat: (peerPhone: String, peerName: String) -> Unit, onOpenSettings: () -> Unit, onLogout: () -> Unit, onInAppNotification: (String) -> Unit) {
    var contacts by remember { mutableStateOf<List<Contact>>(emptyList()) }
    var recentChats by remember { mutableStateOf<Map<String, RecentChat>>(emptyMap()) }
    var showAdd by remember { mutableStateOf(false) }
    var showMenu by remember { mutableStateOf(false) }
    val cleanMy = myPhone.sanitise()

    var longPressedContact by remember { mutableStateOf<Contact?>(null) }
    var showContactActions by remember { mutableStateOf(false) }
    var showEditDialog by remember { mutableStateOf(false) }
    var showDeleteConfirm by remember { mutableStateOf(false) }
    
    // Status state management
    var showStatusDialog by remember { mutableStateOf(false) }
    var showMyStatusView by remember { mutableStateOf(false) }
    var myActiveStatus by remember { mutableStateOf<UserStatus?>(null) }

    // Fetch My Status
    DisposableEffect(cleanMy) {
        val ref = FirebaseDatabase.getInstance().reference.child("statuses").child(cleanMy)
        val listener = object : ValueEventListener {
            override fun onDataChange(snap: DataSnapshot) {
                val status = snap.getValue(UserStatus::class.java)
                if (status != null && status.expiresAt > System.currentTimeMillis()) {
                    myActiveStatus = status
                } else {
                    myActiveStatus = null
                }
            }
            override fun onCancelled(error: DatabaseError) {}
        }
        ref.addValueEventListener(listener)
        onDispose { ref.removeEventListener(listener) }
    }

    DisposableEffect(cleanMy) {
        val ref = FirebaseDatabase.getInstance().reference.child("contacts").child(cleanMy)
        val listener = object : ValueEventListener {
            override fun onDataChange(snap: DataSnapshot) { contacts = snap.children.mapNotNull { it.getValue(Contact::class.java) } }
            override fun onCancelled(error: DatabaseError) {}
        }
        ref.addValueEventListener(listener)
        onDispose { ref.removeEventListener(listener) }
    }

    DisposableEffect(cleanMy) {
        val ref = FirebaseDatabase.getInstance().reference.child("recent_chats").child(cleanMy)
        val listener = object : ValueEventListener {
            override fun onDataChange(snap: DataSnapshot) {
                val map = mutableMapOf<String, RecentChat>()
                snap.children.forEach { child -> child.getValue(RecentChat::class.java)?.let { map[it.phone.sanitise()] = it } }
                recentChats = map
            }
            override fun onCancelled(error: DatabaseError) {}
        }
        ref.addValueEventListener(listener)
        onDispose { ref.removeEventListener(listener) }
    }

    val previousUnreadRef = remember { mutableMapOf<String, Int>() }
    DisposableEffect(cleanMy) {
        val ref = FirebaseDatabase.getInstance().reference.child("recent_chats").child(cleanMy)
        val childListener = object : ChildEventListener {
            override fun onChildAdded(snap: DataSnapshot, prev: String?) {
                val rc = snap.getValue(RecentChat::class.java) ?: return
                previousUnreadRef[rc.phone.sanitise()] = rc.unread
            }
            override fun onChildChanged(snap: DataSnapshot, prev: String?) {
                val rc = snap.getValue(RecentChat::class.java) ?: return
                val peerKey = rc.phone.sanitise()
                val previousUnread = previousUnreadRef[peerKey] ?: 0
                if (rc.unread > 0 && rc.unread > previousUnread) {
                    val senderName = contacts.find { it.phone.sanitise() == peerKey }?.name ?: rc.phone
                    onInAppNotification("$senderName: ${rc.lastMsg}")
                }
                previousUnreadRef[peerKey] = rc.unread
            }
            override fun onChildRemoved(snap: DataSnapshot) {
                val phone = snap.getValue(RecentChat::class.java)?.phone?.sanitise() ?: return
                previousUnreadRef.remove(phone)
            }
            override fun onChildMoved(snap: DataSnapshot, prev: String?) {}
            override fun onCancelled(error: DatabaseError) {}
        }
        ref.addChildEventListener(childListener)
        onDispose { ref.removeEventListener(childListener) }
    }

    if (showAdd) AddContactDialog(myPhone = cleanMy, onDismiss = { showAdd = false }, onAdded = { showAdd = false })

    if (showContactActions && longPressedContact != null) {
        ContactActionsSheet(contact = longPressedContact!!, onDismiss = { showContactActions = false; longPressedContact = null }, onEdit = { showContactActions = false; showEditDialog = true }, onDelete = { showContactActions = false; showDeleteConfirm = true })
    }

    if (showEditDialog && longPressedContact != null) {
        EditContactDialog(myPhone = cleanMy, contact = longPressedContact!!, onDismiss = { showEditDialog = false; longPressedContact = null }, onSaved = { showEditDialog = false; longPressedContact = null })
    }

    if (showDeleteConfirm && longPressedContact != null) {
        val contactToDelete = longPressedContact!!
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false; longPressedContact = null }, containerColor = Palette.Surface,
            title = { Text("Delete Chat", color = Palette.White, fontWeight = FontWeight.Bold, fontSize = 17.sp) },
            text = { Text("This will permanently delete your conversation with ${contactToDelete.name}, remove them from your contacts, and wipe all messages. This cannot be undone.", color = Palette.Muted, fontSize = 14.sp, lineHeight = 20.sp) },
            confirmButton = { Button(onClick = { deleteContact(cleanMy, contactToDelete); showDeleteConfirm = false; longPressedContact = null }, colors = ButtonDefaults.buttonColors(containerColor = Palette.Error)) { Text("Delete Everything", color = Palette.White, fontWeight = FontWeight.Bold) } },
            dismissButton = { TextButton(onClick = { showDeleteConfirm = false; longPressedContact = null }) { Text("Cancel", color = Palette.Muted) } }
        )
    }

    if (showStatusDialog) {
        AddStatusDialog(myPhone = cleanMy, onDismiss = { showStatusDialog = false })
    }

    if (showMyStatusView && myActiveStatus != null) {
        MyStatusViewDialog(myPhone = cleanMy, status = myActiveStatus!!, onDismiss = { showMyStatusView = false })
    }

    val sortedContacts = contacts.sortedByDescending { recentChats[it.phone.sanitise()]?.timestamp ?: 0L }

    Box(Modifier.fillMaxSize().background(Palette.Bg).systemBarsPadding()) {
        Column(Modifier.fillMaxSize()) {
            Row(Modifier.fillMaxWidth().background(Palette.Surface).padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                Column {
                    Text("TEXTO", fontSize = 20.sp, fontWeight = FontWeight.Black, fontFamily = FontFamily.Monospace, color = Palette.Accent)
                    Text(myPhone, fontSize = 11.sp, color = Palette.Muted)
                }
                Box {
                    IconButton(onClick = { showMenu = true }) { Icon(Icons.Default.MoreVert, contentDescription = "Menu", tint = Palette.White) }
                    DropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }, modifier = Modifier.background(Palette.Surface2)) {
                        DropdownMenuItem(text = { Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) { Text("⚙️", fontSize = 16.sp); Text("Settings", color = Palette.White, fontSize = 14.sp) } }, onClick = { showMenu = false; onOpenSettings() })
                        HorizontalDivider(color = Palette.Surface2)
                        DropdownMenuItem(text = { Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) { Text("🚪", fontSize = 16.sp); Text("Sign Out", color = Palette.Error, fontSize = 14.sp) } }, onClick = { showMenu = false; onLogout() })
                    }
                }
            }
            HorizontalDivider(color = Palette.Surface2)

            if (sortedContacts.isEmpty()) {
                Box(Modifier.weight(1f).fillMaxWidth(), Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("👥", fontSize = 48.sp); Text("No contacts yet", fontSize = 16.sp, color = Palette.White, fontWeight = FontWeight.Bold); Text("Tap the + button to add someone", fontSize = 13.sp, color = Palette.Muted)
                    }
                }
            } else {
                LazyColumn(Modifier.weight(1f)) {
                    items(items = sortedContacts, key = { it.phone }) { contact ->
                        val recent = recentChats[contact.phone.sanitise()]
                        val preview = if (recent?.lastMsg?.contains("🔒") == true) recent.lastMsg else "🔒 Secure Message"
                        ContactRow(
                            contact = contact, lastMsg = preview, lastTs = recent?.timestamp ?: 0L, unread = recent?.unread ?: 0,
                            onClick = { onOpenChat(contact.phone, contact.name) }, onLongClick = { longPressedContact = contact; showContactActions = true }
                        )
                        HorizontalDivider(color = Palette.Surface2, thickness = 0.5.dp, modifier = Modifier.padding(start = 72.dp))
                    }
                }
            }

            // Bottom Section containing FAB and Status Split-Bar
            Box(modifier = Modifier.fillMaxWidth().background(Palette.Bg).padding(horizontal = 16.dp, vertical = 12.dp)) {
                Column {
                    // FAB Row (Aligned End)
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        FloatingActionButton(onClick = { showAdd = true }, containerColor = Palette.Accent, contentColor = Color.Black, modifier = Modifier.size(56.dp)) { 
                            Text("+", fontSize = 28.sp, fontWeight = FontWeight.Bold) 
                        }
                    }
                    
                    Spacer(Modifier.height(16.dp))
                    
                    // Split Status Bar
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(20.dp))
                            .background(Palette.Surface)
                            .border(1.dp, Palette.Surface2, RoundedCornerShape(20.dp)),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // Part 1: The '+' Button to Add Status
                        IconButton(
                            onClick = { showStatusDialog = true }, 
                            modifier = Modifier.padding(4.dp)
                        ) {
                            Box(Modifier.size(36.dp).clip(CircleShape).background(Palette.AccentDim), Alignment.Center) {
                                Text("+", fontSize = 20.sp, color = Palette.Accent, fontWeight = FontWeight.Bold)
                            }
                        }

                        // Part 2: Clickable Status Area
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clickable {
                                    if (myActiveStatus != null) showMyStatusView = true 
                                    else showStatusDialog = true
                                }
                                .padding(vertical = 14.dp, horizontal = 8.dp)
                        ) {
                            Text(
                                text = myActiveStatus?.text?.let { "Status: $it" } ?: "My Status: Tap to add...",
                                color = if (myActiveStatus != null) Palette.White else Palette.Muted,
                                fontSize = 15.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun AddStatusDialog(myPhone: String, onDismiss: () -> Unit) {
    var statusText by remember { mutableStateOf("") }
    var durationInput by remember { mutableStateOf("") }
    var isSaving by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss, containerColor = Palette.Surface,
        title = { Text("Update Status", color = Palette.White, fontWeight = FontWeight.Bold) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                OutlinedTextField(
                    value = statusText, 
                    onValueChange = { statusText = it }, 
                    label = { Text("What's on your mind?", color = Palette.Muted) }, 
                    colors = textoFieldColors(), 
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = durationInput,
                    onValueChange = { durationInput = it },
                    label = { Text("Duration (in hours)", color = Palette.Muted) },
                    placeholder = { Text("e.g. 24", color = Palette.Muted) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    colors = textoFieldColors(),
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            Button(onClick = {
                val hours = durationInput.toLongOrNull()
                if (hours != null && hours > 0) {
                    isSaving = true
                    val now = System.currentTimeMillis()
                    val expiresAt = now + (hours * 60 * 60 * 1000L)
                    val status = UserStatus(text = statusText.trim(), timestamp = now, expiresAt = expiresAt)
                    FirebaseDatabase.getInstance().reference.child("statuses").child(myPhone).setValue(status)
                        .addOnCompleteListener { isSaving = false; onDismiss() }
                }
            }, enabled = !isSaving && statusText.isNotBlank() && durationInput.isNotBlank(), colors = ButtonDefaults.buttonColors(containerColor = Palette.Accent)) {
                if (isSaving) CircularProgressIndicator(Modifier.size(16.dp), color = Color.Black, strokeWidth = 2.dp) else Text("Share", color = Color.Black, fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel", color = Palette.Muted) } }
    )
}

@Composable
fun MyStatusViewDialog(myPhone: String, status: UserStatus, onDismiss: () -> Unit) {
    var showMenu by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Palette.Surface,
        title = {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("Current Status", color = Palette.White, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                Box {
                    IconButton(onClick = { showMenu = true }) { 
                        Icon(Icons.Default.MoreVert, contentDescription = "Menu", tint = Palette.White) 
                    }
                    DropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }, modifier = Modifier.background(Palette.Surface2)) {
                        DropdownMenuItem(
                            text = { Text("Delete Status", color = Palette.Error) },
                            onClick = {
                                showMenu = false
                                FirebaseDatabase.getInstance().reference.child("statuses").child(myPhone).removeValue()
                                onDismiss()
                            }
                        )
                    }
                }
            }
        },
        text = {
            Column {
                Text(status.text, color = Palette.White, fontSize = 16.sp)
                Spacer(Modifier.height(8.dp))
                val remainingHours = ((status.expiresAt - System.currentTimeMillis()) / 3600000).coerceAtLeast(0)
                Text("Expires in approx $remainingHours hours", color = Palette.Muted, fontSize = 12.sp)
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Close", color = Palette.Accent) }
        }
    )
}


@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ContactRow(contact: Contact, lastMsg: String, lastTs: Long, unread: Int, onClick: () -> Unit, onLongClick: () -> Unit) {
    var profilePicBase64 by remember { mutableStateOf<String?>(null) }
    var activeStatus by remember { mutableStateOf<UserStatus?>(null) }
    var showProfilePopOut by remember { mutableStateOf(false) }

    DisposableEffect(contact.phone) {
        val ref = FirebaseDatabase.getInstance().reference.child("users").child(contact.phone.sanitise()).child("profilePicBase64")
        val listener = object : ValueEventListener {
            override fun onDataChange(snap: DataSnapshot) { profilePicBase64 = snap.getValue(String::class.java) }
            override fun onCancelled(error: DatabaseError) {}
        }
        ref.addValueEventListener(listener)
        onDispose { ref.removeEventListener(listener) }
    }

    // Status Listener
    DisposableEffect(contact.phone) {
        val ref = FirebaseDatabase.getInstance().reference.child("statuses").child(contact.phone.sanitise())
        val listener = object : ValueEventListener {
            override fun onDataChange(snap: DataSnapshot) { activeStatus = snap.getValue(UserStatus::class.java) }
            override fun onCancelled(error: DatabaseError) {}
        }
        ref.addValueEventListener(listener)
        onDispose { ref.removeEventListener(listener) }
    }

    if (showProfilePopOut) {
        ProfilePopOutDialog(name = contact.name, base64Pic = profilePicBase64, statusText = activeStatus?.text.takeIf { activeStatus?.expiresAt ?: 0 > System.currentTimeMillis() }, onDismiss = { showProfilePopOut = false })
    }

    val hasValidStatus = activeStatus != null && activeStatus!!.expiresAt > System.currentTimeMillis()
    val ringModifier = if (hasValidStatus) Modifier.border(2.dp, Palette.Accent, CircleShape) else Modifier

    Row(Modifier.fillMaxWidth().combinedClickable(onClick = onClick, onLongClick = onLongClick).padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
        // Tapping only the box triggers the pop-out
        Box(Modifier.size(50.dp).clip(CircleShape).background(Palette.Surface2).then(ringModifier).clickable { showProfilePopOut = true }.padding(if (hasValidStatus) 3.dp else 0.dp), Alignment.Center) {
            if (!profilePicBase64.isNullOrBlank()) {
                val imageBytes = Base64.decode(profilePicBase64, Base64.DEFAULT)
                AsyncImage(model = imageBytes, contentDescription = "Profile Pic", modifier = Modifier.fillMaxSize().clip(CircleShape), contentScale = ContentScale.Crop)
            } else {
                Text(contact.name.take(2).uppercase(), fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Palette.Accent)
            }
        }
        Column(Modifier.weight(1f)) {
            Text(contact.name, fontSize = 16.sp, fontWeight = FontWeight.SemiBold, color = Palette.White)
            Text(text = lastMsg.ifEmpty { contact.phone }, fontSize = 13.sp, color = Palette.Muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(4.dp)) {
            if (lastTs > 0) Text(formatTimestamp(lastTs), fontSize = 11.sp, color = Palette.Muted)
            if (unread > 0) {
                Box(Modifier.size(20.dp).clip(CircleShape).background(Palette.Accent), Alignment.Center) {
                    Text(unread.toString(), fontSize = 11.sp, color = Color.Black, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

@Composable
fun ProfilePopOutDialog(name: String, base64Pic: String?, statusText: String?, onDismiss: () -> Unit) {
    Dialog(onDismissRequest = onDismiss) {
        Column(Modifier.clip(RoundedCornerShape(8.dp)).background(Palette.Surface)) {
            Box(Modifier.fillMaxWidth().aspectRatio(1f).background(Palette.Surface2)) {
                if (!base64Pic.isNullOrBlank()) {
                    val imgBytes = Base64.decode(base64Pic, Base64.DEFAULT)
                    AsyncImage(model = imgBytes, contentDescription = null, modifier = Modifier.fillMaxSize(), contentScale = ContentScale.Crop)
                } else {
                    Text(name.take(2).uppercase(), modifier = Modifier.align(Alignment.Center), fontSize = 64.sp, fontWeight = FontWeight.Black, color = Palette.Accent)
                }
                Box(Modifier.align(Alignment.TopStart).fillMaxWidth().background(Color.Black.copy(alpha=0.4f)).padding(12.dp)) {
                    Text(name, color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                }
            }
            if (statusText != null) {
                Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("💭", fontSize = 20.sp, modifier = Modifier.padding(end = 12.dp))
                    Text(statusText, color = Palette.White, fontSize = 14.sp)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContactActionsSheet(contact: Contact, onDismiss: () -> Unit, onEdit: () -> Unit, onDelete: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = Palette.Surface, scrimColor = Color.Black.copy(alpha = 0.5f), shape = RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp)) {
        Column(Modifier.fillMaxWidth().padding(bottom = 32.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Box(Modifier.width(40.dp).height(4.dp).clip(RoundedCornerShape(2.dp)).background(Palette.Muted.copy(alpha = 0.4f)))
            Spacer(Modifier.height(20.dp))
            Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                Box(Modifier.size(48.dp).clip(CircleShape).background(Palette.AccentDim).border(1.5.dp, Palette.Accent, CircleShape), Alignment.Center) { Text(contact.name.take(2).uppercase(), fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Palette.Accent) }
                Column { Text(contact.name, fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Palette.White); Text(contact.phone, fontSize = 12.sp, color = Palette.Muted, fontFamily = FontFamily.Monospace) }
            }
            Spacer(Modifier.height(16.dp))
            HorizontalDivider(color = Palette.Surface2, modifier = Modifier.padding(horizontal = 20.dp))
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth().clickable(onClick = onEdit).padding(horizontal = 20.dp, vertical = 16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Box(Modifier.size(40.dp).clip(CircleShape).background(Palette.AccentDim), Alignment.Center) { Text("✏️", fontSize = 18.sp) }
                Column(Modifier.weight(1f)) { Text("Edit ${contact.name}", fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = Palette.White); Text("Change display name", fontSize = 12.sp, color = Palette.Muted) }
            }
            HorizontalDivider(color = Palette.Surface2, modifier = Modifier.padding(horizontal = 20.dp))
            Row(Modifier.fillMaxWidth().clickable(onClick = onDelete).padding(horizontal = 20.dp, vertical = 16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Box(Modifier.size(40.dp).clip(CircleShape).background(Palette.Error.copy(alpha = 0.15f)), Alignment.Center) { Text("🗑️", fontSize = 18.sp) }
                Column(Modifier.weight(1f)) { Text("Delete Chat", fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = Palette.Error); Text("Remove contact + wipe all messages", fontSize = 12.sp, color = Palette.Muted) }
            }
        }
    }
}

@Composable
fun EditContactDialog(myPhone: String, contact: Contact, onDismiss: () -> Unit, onSaved: () -> Unit) {
    var newName by remember { mutableStateOf(contact.name) }
    var isSaving by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss, containerColor = Palette.Surface,
        title = { Text("Rename Contact", color = Palette.White, fontWeight = FontWeight.Bold, fontSize = 18.sp) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Edit the display name for ${contact.phone}", fontSize = 12.sp, color = Palette.Muted)
                Spacer(Modifier.height(4.dp))
                OutlinedTextField(value = newName, onValueChange = { newName = it }, label = { Text("Display Name", color = Palette.Muted) }, singleLine = true, colors = textoFieldColors(), modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (newName.isBlank()) return@Button; isSaving = true
                    FirebaseDatabase.getInstance().reference.child("contacts").child(myPhone).child(contact.phone.sanitise()).child("name").setValue(newName.trim())
                        .addOnSuccessListener { isSaving = false; onSaved() }.addOnFailureListener { isSaving = false; onSaved() }
                }, enabled = !isSaving && newName.isNotBlank(), colors = ButtonDefaults.buttonColors(containerColor = Palette.Accent)
            ) { if (isSaving) CircularProgressIndicator(Modifier.size(16.dp), color = Color.Black, strokeWidth = 2.dp) else Text("Save", color = Color.Black, fontWeight = FontWeight.Bold) }
        }, dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel", color = Palette.Muted) } }
    )
}

fun deleteContact(myPhone: String, contact: Contact) {
    val db = FirebaseDatabase.getInstance().reference
    val cleanMy   = myPhone.sanitise()
    val cleanPeer = contact.phone.sanitise()
    val roomId    = buildRoomId(cleanMy, cleanPeer)
    db.child("contacts").child(cleanMy).child(cleanPeer).removeValue()
    db.child("recent_chats").child(cleanMy).child(cleanPeer).removeValue()
    db.child("recent_chats").child(cleanPeer).child(cleanMy).removeValue()
    db.child("messages").child(roomId).removeValue()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(myPhone: String, onBack: () -> Unit) {
    BackHandler { onBack() }
    val context = LocalContext.current
    val cleanMy = myPhone.sanitise()
    val db = FirebaseDatabase.getInstance().reference

    var profileBase64 by remember { mutableStateOf<String?>(null) }
    var pendingBase64 by remember { mutableStateOf<String?>(null) }
    var displayName by remember { mutableStateOf("") }
    var aboutText   by remember { mutableStateOf("") }
    var isSaving by remember { mutableStateOf(false) }

    var showSavedDialog   by remember { mutableStateOf(false) }
    var showDeleteDpDialog by remember { mutableStateOf(false) }
    var showDpMenu        by remember { mutableStateOf(false) }

    LaunchedEffect(cleanMy) {
        db.child("users").child(cleanMy).get().addOnSuccessListener { snap ->
            profileBase64 = snap.child("profilePicBase64").getValue(String::class.java)
            displayName   = snap.child("name").getValue(String::class.java) ?: ""
            aboutText     = snap.child("about").getValue(String::class.java) ?: ""
        }
    }

    val cropLauncher = rememberLauncherForActivityResult(CropImageContract()) { result ->
        if (result.isSuccessful && result.uriContent != null) {
            val base64 = encodeImageUriToBase64(context, result.uriContent!!)
            if (base64 != null) pendingBase64 = base64
        }
    }

    val imagePickerLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) {
            val options = CropImageOptions(imageSourceIncludeGallery = true, imageSourceIncludeCamera = false, aspectRatioX = 1, aspectRatioY = 1, fixAspectRatio = true)
            cropLauncher.launch(CropImageContractOptions(uri, options))
        }
    }

    if (showDeleteDpDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDpDialog = false }, containerColor = Palette.Surface,
            title = { Text("Remove Profile Picture", color = Palette.White, fontWeight = FontWeight.Bold) },
            text  = { Text("Your profile picture will be removed.", color = Palette.Muted, fontSize = 14.sp) },
            confirmButton = {
                Button(onClick = {
                    showDeleteDpDialog = false; profileBase64 = null; pendingBase64 = null
                    db.child("users").child(cleanMy).child("profilePicBase64").removeValue()
                }, colors = ButtonDefaults.buttonColors(containerColor = Palette.Error)) {
                    Text("Remove", color = Palette.White, fontWeight = FontWeight.Bold)
                }
            }, dismissButton = { TextButton(onClick = { showDeleteDpDialog = false }) { Text("Cancel", color = Palette.Muted) } }
        )
    }

    if (showSavedDialog) {
        AlertDialog(
            onDismissRequest = { showSavedDialog = false }, containerColor = Palette.Surface,
            title = { Row(verticalAlignment = Alignment.CenterVertically) { Text("✅  Profile Saved", color = Palette.White, fontWeight = FontWeight.Bold, fontSize = 18.sp) } },
            text = { Text("Your profile has been updated successfully.", color = Palette.Muted, fontSize = 14.sp) },
            confirmButton = { Button(onClick = { showSavedDialog = false }, colors = ButtonDefaults.buttonColors(containerColor = Palette.Accent)) { Text("OK", color = Color.Black, fontWeight = FontWeight.Bold) } }
        )
    }

    Column(Modifier.fillMaxSize().background(Palette.Bg).systemBarsPadding()) {
        Row(Modifier.fillMaxWidth().background(Palette.Surface).padding(horizontal = 4.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = Palette.Accent) }
            Text("Settings", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Palette.White, modifier = Modifier.weight(1f))
        }
        HorizontalDivider(color = Palette.Surface2)

        LazyColumn(Modifier.fillMaxSize().padding(horizontal = 20.dp), contentPadding = PaddingValues(bottom = 48.dp)) {
            item {
                Spacer(Modifier.height(32.dp))
                val displayBase64 = pendingBase64 ?: profileBase64
                val hasPhoto = !displayBase64.isNullOrBlank()

                Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(contentAlignment = Alignment.BottomEnd) {
                        Box(Modifier.size(120.dp).clip(CircleShape).background(Brush.radialGradient(listOf(Palette.Accent.copy(alpha = 0.35f), Color.Transparent))), Alignment.Center) {
                            Box(Modifier.size(110.dp).clip(CircleShape).background(Palette.Surface2).border(2.5.dp, Palette.Accent, CircleShape), Alignment.Center) {
                                if (hasPhoto) {
                                    val imageBytes = Base64.decode(displayBase64, Base64.DEFAULT)
                                    AsyncImage(model = imageBytes, contentDescription = "Profile", modifier = Modifier.fillMaxSize().clip(CircleShape), contentScale = ContentScale.Crop)
                                } else {
                                    Text(displayName.take(2).uppercase().ifEmpty { "?" }, fontSize = 38.sp, fontWeight = FontWeight.Black, color = Palette.Accent)
                                }
                            }
                        }
                        Box(Modifier.size(34.dp).clip(CircleShape).background(Palette.Surface).border(1.5.dp, Palette.Accent, CircleShape).clickable { showDpMenu = true }, Alignment.Center) { Text("📷", fontSize = 15.sp) }
                        DropdownMenu(expanded = showDpMenu, onDismissRequest = { showDpMenu = false }, modifier = Modifier.background(Palette.Surface2)) {
                            DropdownMenuItem(text = { Text("🖼️ Change Photo", color = Palette.White) }, onClick = { showDpMenu = false; imagePickerLauncher.launch("image/*") })
                            if (hasPhoto) {
                                HorizontalDivider(color = Palette.Surface2)
                                DropdownMenuItem(text = { Text("🗑️ Delete Photo", color = Palette.Error) }, onClick = { showDpMenu = false; showDeleteDpDialog = true })
                            }
                        }
                    }
                    if (pendingBase64 != null) {
                        Spacer(Modifier.height(8.dp))
                        Text("⚠️ Tap Save Profile to apply", fontSize = 11.sp, color = Palette.Accent)
                    }
                    Spacer(Modifier.height(10.dp))
                    Text(myPhone, color = Palette.Muted, fontFamily = FontFamily.Monospace)
                }
                Spacer(Modifier.height(32.dp))
            }
            item { Text("PROFILE INFO", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Palette.Accent); Spacer(Modifier.height(12.dp)) }
            item { OutlinedTextField(value = displayName, onValueChange = { displayName = it }, label = { Text("Display Name", color = Palette.Muted) }, singleLine = true, colors = textoFieldColors(), modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)); Spacer(Modifier.height(14.dp)) }
            item { OutlinedTextField(value = aboutText, onValueChange = { aboutText = it }, label = { Text("About", color = Palette.Muted) }, maxLines = 3, colors = textoFieldColors(), modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)); Spacer(Modifier.height(28.dp)) }

            item {
                Button(
                    onClick = {
                        isSaving = true
                        val updates = mutableMapOf<String, Any>("name" to displayName.trim(), "about" to aboutText.trim())
                        if (pendingBase64 != null) updates["profilePicBase64"] = pendingBase64!!

                        db.child("users").child(cleanMy).updateChildren(updates).addOnCompleteListener { task ->
                            isSaving = false
                            if (task.isSuccessful) {
                                if (pendingBase64 != null) { profileBase64 = pendingBase64; pendingBase64 = null }
                                showSavedDialog = true
                            }
                        }
                    },
                    enabled = !isSaving, colors = ButtonDefaults.buttonColors(containerColor = Palette.Accent), modifier = Modifier.fillMaxWidth().height(52.dp).clip(RoundedCornerShape(14.dp))
                ) {
                    if (isSaving) CircularProgressIndicator(color = Color.Black, modifier = Modifier.size(20.dp), strokeWidth = 2.5.dp)
                    else Text("Save Profile", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                }
                Spacer(Modifier.height(32.dp))
            }
        }
    }
}

@Composable
fun AddContactDialog(myPhone: String, onDismiss: () -> Unit, onAdded: () -> Unit) {
    var phone by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var isSaving by remember { mutableStateOf(false) }
    var liveProfileBase64 by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(phone) {
        val cleanTyped = phone.sanitise()
        if (cleanTyped.length >= 10) {
            FirebaseDatabase.getInstance().reference.child("users").child(cleanTyped).child("profilePicBase64").get()
                .addOnSuccessListener { liveProfileBase64 = it.getValue(String::class.java) }.addOnFailureListener { liveProfileBase64 = null }
        } else { liveProfileBase64 = null }
    }

    AlertDialog(
        onDismissRequest = onDismiss, containerColor = Palette.Surface,
        title = { Text("Add Contact", color = Palette.White, fontWeight = FontWeight.Bold, fontSize = 18.sp) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp), horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                if (!liveProfileBase64.isNullOrBlank()) {
                    val imageBytes = Base64.decode(liveProfileBase64, Base64.DEFAULT)
                    AsyncImage(model = imageBytes, contentDescription = "Live Preview", modifier = Modifier.size(60.dp).clip(CircleShape).border(2.dp, Palette.Accent, CircleShape), contentScale = ContentScale.Crop)
                }
                OutlinedTextField(value = phone, onValueChange = { phone = it }, label = { Text("Phone Number (+91...)", color = Palette.Muted) }, singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone), colors = textoFieldColors(), modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Display Name", color = Palette.Muted) }, placeholder = { Text("e.g. Arjun", color = Palette.Muted) }, singleLine = true, colors = textoFieldColors(), modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            Button(onClick = {
                if (name.isBlank() || phone.isBlank()) return@Button; isSaving = true
                val contact = Contact(phone = phone.sanitise(), name = name.trim(), addedAt = System.currentTimeMillis())
                FirebaseDatabase.getInstance().reference.child("contacts").child(myPhone).child(phone.sanitise()).setValue(contact)
                    .addOnSuccessListener { isSaving = false; onAdded() }.addOnFailureListener { isSaving = false }
            }, enabled = !isSaving, colors = ButtonDefaults.buttonColors(containerColor = Palette.Accent)) { if (isSaving) CircularProgressIndicator(Modifier.size(16.dp), color = Color.Black, strokeWidth = 2.dp) else Text("Save", color = Color.Black, fontWeight = FontWeight.Bold) }
        }, dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel", color = Palette.Muted) } }
    )
}

@Composable
fun ChatScreen(myPhone: String, peerPhone: String, peerName: String, onBack: () -> Unit) {
    BackHandler { onBack() }
    val context = LocalContext.current
    val messages = remember { mutableStateListOf<ChatMessage>() }
    var inputText by remember { mutableStateOf("") }
    val listState = rememberLazyListState()
    val cleanMy = myPhone.sanitise()
    val cleanPeer = peerPhone.sanitise()
    val roomId = buildRoomId(cleanMy, cleanPeer)
    val dbRoot = remember { FirebaseDatabase.getInstance().reference }

    var aesKey by remember { mutableStateOf<SecretKeySpec?>(null) }
    var chatStatus by remember { mutableStateOf("Establishing secure connection…") }
    var peerProfilePicBase64 by remember { mutableStateOf<String?>(null) }
    var peerPresence by remember { mutableStateOf("offline") }
    var activeStatus by remember { mutableStateOf<UserStatus?>(null) }
    var showProfilePopOut by remember { mutableStateOf(false) }

    LaunchedEffect(cleanPeer) { dbRoot.child("recent_chats").child(cleanMy).child(cleanPeer).child("unread").setValue(0) }
    LaunchedEffect(Unit) {
        val myPresenceRef = dbRoot.child("presence").child(cleanMy).child("status")
        myPresenceRef.setValue("online"); myPresenceRef.onDisconnect().setValue("offline")
    }
    LaunchedEffect(inputText) {
        val myPresenceRef = dbRoot.child("presence").child(cleanMy).child("status")
        if (inputText.isNotBlank()) myPresenceRef.setValue("typing...") else myPresenceRef.setValue("online")
    }
    LaunchedEffect(cleanPeer) {
        dbRoot.child("users").child(cleanPeer).child("profilePicBase64").get().addOnSuccessListener { peerProfilePicBase64 = it.getValue(String::class.java) }
        val presenceRef = dbRoot.child("presence").child(cleanPeer).child("status")
        val listener = object : ValueEventListener {
            override fun onDataChange(snap: DataSnapshot) { peerPresence = snap.getValue(String::class.java) ?: "offline" }
            override fun onCancelled(error: DatabaseError) {}
        }
        presenceRef.addValueEventListener(listener)

        // Status Check
        dbRoot.child("statuses").child(cleanPeer).get().addOnSuccessListener { snap -> activeStatus = snap.getValue(UserStatus::class.java) }
    }
    LaunchedEffect(cleanPeer) {
        KeyRegistry.fetchPeerPublicKey(cleanPeer) { peerPubKeyBase64 ->
            if (peerPubKeyBase64 == null) { chatStatus = "Peer not registered for E2EE." } else {
                val peerPubKey = SignalHandshakeManager.reconstructPublicKey(peerPubKeyBase64)
                val myPrivKey  = SignalKeyManager.getPrivateKey()
                if (peerPubKey != null && myPrivKey != null) {
                    aesKey = SignalHandshakeManager.deriveAesKey(myPrivKey, peerPubKey)
                    chatStatus = if (aesKey != null) "🔒 E2EE" else "Failed to derive session key."
                } else { chatStatus = "Crypto initialisation failed." }
            }
        }
    }
    DisposableEffect(aesKey) {
        val currentKey = aesKey ?: return@DisposableEffect onDispose {}
        val ref = dbRoot.child("messages").child(roomId)
        val listener = object : ChildEventListener {
            override fun onChildAdded(snap: DataSnapshot, previousChildName: String?) {
                val msg = snap.getValue(ChatMessage::class.java) ?: return
                val display = msg.copy(text = SignalCryptoEngine.decrypt(msg.text, currentKey))
                if (messages.none { it.id == display.id }) messages.add(display)
                if (display.senderId != cleanMy && display.status != "read") snap.ref.child("status").setValue("read")
            }
            override fun onChildChanged(snap: DataSnapshot, previousChildName: String?) {
                val msg = snap.getValue(ChatMessage::class.java) ?: return
                val display = msg.copy(text = SignalCryptoEngine.decrypt(msg.text, currentKey))
                val idx = messages.indexOfFirst { it.id == display.id }
                if (idx >= 0) messages[idx] = display
            }
            override fun onChildRemoved(snap: DataSnapshot) {}
            override fun onChildMoved(snap: DataSnapshot, previousChildName: String?) {}
            override fun onCancelled(error: DatabaseError) {}
        }
        ref.addChildEventListener(listener)
        onDispose { ref.removeEventListener(listener); messages.clear() }
    }
    LaunchedEffect(messages.size) { if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1) }

    if (showProfilePopOut) {
        ProfilePopOutDialog(name = peerName, base64Pic = peerProfilePicBase64, statusText = activeStatus?.text.takeIf { activeStatus?.expiresAt ?: 0 > System.currentTimeMillis() }, onDismiss = { showProfilePopOut = false })
    }

    val hasValidStatus = activeStatus != null && activeStatus!!.expiresAt > System.currentTimeMillis()
    val ringModifier = if (hasValidStatus) Modifier.border(2.dp, Palette.Accent, CircleShape) else Modifier

    // The safeDrawingPadding ensures the keyboard pushes the UI up perfectly
    Column(Modifier.fillMaxSize().background(Palette.Bg).safeDrawingPadding()) {
        Row(Modifier.fillMaxWidth().background(Palette.Surface).padding(horizontal = 8.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = Palette.Accent) }
            Box(Modifier.size(40.dp).clip(CircleShape).background(Palette.Surface2).then(ringModifier).clickable { showProfilePopOut = true }.padding(if (hasValidStatus) 3.dp else 0.dp), Alignment.Center) {
                if (!peerProfilePicBase64.isNullOrBlank()) {
                    val imageBytes = Base64.decode(peerProfilePicBase64, Base64.DEFAULT)
                    AsyncImage(model = imageBytes, contentDescription = "Peer Pic", modifier = Modifier.fillMaxSize().clip(CircleShape), contentScale = ContentScale.Crop)
                } else { Text(peerName.take(2).uppercase(), fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Palette.Accent) }
            }
            Column(Modifier.weight(1f)) {
                Text(peerName, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = Palette.White, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(chatStatus, fontSize = 11.sp, color = if (aesKey != null) Palette.Accent else Palette.Error)
                    Text("• $peerPresence", fontSize = 11.sp, color = if (peerPresence == "typing...") Palette.Accent else Palette.Muted)
                }
            }
        }
        HorizontalDivider(color = Palette.Surface2)
        when {
            aesKey == null -> Box(Modifier.weight(1f).fillMaxWidth(), Alignment.Center) { CircularProgressIndicator(color = Palette.Accent) }
            messages.isEmpty() -> Box(Modifier.weight(1f).fillMaxWidth(), Alignment.Center) { Text("No messages yet. Say hello! 👋", fontSize = 14.sp, color = Palette.Muted) }
            else -> LazyColumn(state = listState, modifier = Modifier.weight(1f).padding(horizontal = 10.dp), verticalArrangement = Arrangement.spacedBy(4.dp), contentPadding = PaddingValues(vertical = 10.dp)) {
                items(items = messages, key = { it.id }) { msg -> ChatBubble(msg = msg, isMine = msg.senderId == cleanMy, context = context) }
            }
        }
        Column(Modifier.background(Palette.Surface)) {
            HorizontalDivider(color = Palette.Surface2)
            Row(Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = inputText, onValueChange = { inputText = it }, placeholder = { Text("Message…", color = Palette.Muted) }, singleLine = false, maxLines = 4, enabled = aesKey != null, colors = textoFieldColors(), shape = RoundedCornerShape(20.dp), modifier = Modifier.weight(1f))
                val canSend = inputText.isNotBlank() && aesKey != null
                Box(Modifier.size(48.dp).clip(CircleShape).background(if (canSend) Palette.Accent else Palette.Surface2).clickable(enabled = canSend) { sendTextMessage(dbRoot, roomId, cleanMy, cleanPeer, inputText.trim(), aesKey!!); inputText = "" }, Alignment.Center) { Icon(Icons.AutoMirrored.Filled.Send, "Send", tint = if (canSend) Color.Black else Palette.Muted, modifier = Modifier.size(20.dp)) }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// REUSABLE COMPONENTS
// ─────────────────────────────────────────────────────────────────────────────
@Composable
fun VaultRow(label: String, value: String) { Row(Modifier.fillMaxWidth(), Arrangement.SpaceBetween, Alignment.CenterVertically) { Text(label, fontSize = 12.sp, color = Palette.Muted); Text(value, fontSize = 12.sp, color = Palette.Accent, fontFamily = FontFamily.Monospace) } }
@Composable
fun textoFieldColors() = OutlinedTextFieldDefaults.colors(focusedBorderColor = Palette.Accent, unfocusedBorderColor = Palette.Muted, focusedTextColor = Palette.White, unfocusedTextColor = Palette.White, cursorColor = Palette.Accent)
@Composable
fun ChatBubble(msg: ChatMessage, isMine: Boolean, context: Context) {
    val bubbleColor = if (isMine) Palette.BubbleOut else Palette.BubbleIn
    val textColor   = if (isMine) Color.Black else Palette.White
    val shape = if (isMine) RoundedCornerShape(topStart = 18.dp, topEnd = 4.dp, bottomEnd = 18.dp, bottomStart = 18.dp) else RoundedCornerShape(topStart = 4.dp, topEnd = 18.dp, bottomEnd = 18.dp, bottomStart = 18.dp)
    Column(Modifier.fillMaxWidth(), horizontalAlignment = if (isMine) Alignment.End else Alignment.Start) {
        Box(Modifier.widthIn(min = 60.dp, max = 280.dp).clip(shape).background(bubbleColor).padding(horizontal = 12.dp, vertical = 8.dp)) {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(msg.text, fontSize = 15.sp, color = textColor, lineHeight = 20.sp)
                Row(Modifier.fillMaxWidth(), Arrangement.End, Alignment.CenterVertically) {
                    Text(formatTimestamp(msg.timestamp), fontSize = 10.sp, color = if (isMine) Color.Black.copy(alpha = 0.55f) else Palette.Muted)
                    if (isMine) { Spacer(Modifier.width(4.dp)); Text(statusTick(msg.status), fontSize = 11.sp, color = if (msg.status == "read") Color(0xFF0099FF) else Color.Black.copy(alpha = 0.55f)) }
                }
            }
        }
    }
}
@Composable
fun AuthStatusCard(state: AuthState) {
    data class Step(val icon: String, val label: String, val done: Boolean, val active: Boolean)
    val steps: List<Step> = when (state) {
        is AuthState.Idle -> emptyList()
        is AuthState.SendingOtp -> listOf(Step("📡", "Sending OTP…", false, true))
        is AuthState.AwaitingCode -> listOf(Step("📡", "OTP sent", true, false))
        is AuthState.VerifyingOtp -> listOf(Step("📡", "OTP sent", true, false), Step("🔐", "Verifying OTP…", false, true))
        is AuthState.GeneratingKey -> listOf(Step("📡", "OTP sent", true, false), Step("🔐", "OTP verified", true, false), Step("🗝️", "Generating EC key…", false, true))
        is AuthState.PublishingKey -> listOf(Step("📡", "OTP sent", true, false), Step("🔐", "OTP verified", true, false), Step("🗝️", "Identity key secured", true, false), Step("☁️", "Publishing key & profile…", false, true))
        is AuthState.Done -> listOf(Step("✅", "Vault ready!", true, false))
        is AuthState.AuthError -> listOf(Step("❌", "Error — see below", false, false))
    }
    if (steps.isEmpty()) return
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Palette.Surface).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        steps.forEach { s -> Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) { if (s.active && !s.done) CircularProgressIndicator(Modifier.size(16.dp), color = Palette.Accent, strokeWidth = 2.dp) else Text(if (s.done) "✅" else "⬜", fontSize = 14.sp); Text("${s.icon}  ${s.label}", color = if (s.done || s.active) Palette.White else Palette.Muted, fontSize = 12.sp, fontFamily = FontFamily.Monospace) } }
        if (state is AuthState.AuthError) Text("❌  ${state.message}", color = Palette.Error, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FIREBASE SEND HELPERS
// ─────────────────────────────────────────────────────────────────────────────
fun sendTextMessage(dbRoot: DatabaseReference, roomId: String, myPhone: String, peerPhone: String, plainText: String, aesKey: SecretKeySpec) {
    val msgRef = dbRoot.child("messages").child(roomId).push(); val msgId  = msgRef.key ?: return; val ts     = System.currentTimeMillis()
    val msg = ChatMessage(id = msgId, text = SignalCryptoEngine.encrypt(plainText, aesKey), senderId = myPhone, timestamp = ts, status = "sending", type = MsgType.TEXT.name)
    msgRef.setValue(msg).addOnSuccessListener { msgRef.child("status").setValue("sent"); Handler(Looper.getMainLooper()).postDelayed({ msgRef.child("status").setValue("delivered") }, 1200) }
    updateRecentChats(dbRoot, myPhone, peerPhone, "🔒 Secure Message", ts)
}
fun updateRecentChats(dbRoot: DatabaseReference, myPhone: String, peerPhone: String, preview: String, ts: Long) {
    dbRoot.child("recent_chats").child(myPhone).child(peerPhone).setValue(RecentChat(phone = peerPhone, lastMsg = preview, timestamp = ts, unread = 0))
    dbRoot.child("recent_chats").child(peerPhone).child(myPhone).setValue(RecentChat(phone = myPhone, lastMsg = preview, timestamp = ts, unread = 1))
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTH LOGIC
// ─────────────────────────────────────────────────────────────────────────────
fun sendOtp(phone: String, activity: ComponentActivity, auth: FirebaseAuth, onCodeSent: (String) -> Unit, onAutoVerified: (PhoneAuthCredential) -> Unit, onError: (String) -> Unit) {
    PhoneAuthProvider.verifyPhoneNumber(PhoneAuthOptions.newBuilder(auth).setPhoneNumber(phone).setTimeout(60L, TimeUnit.SECONDS).setActivity(activity).setCallbacks(object : PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
        override fun onVerificationCompleted(cred: PhoneAuthCredential) { onAutoVerified(cred) }
        override fun onVerificationFailed(e: com.google.firebase.FirebaseException) { onError(e.message ?: "OTP send failed") }
        override fun onCodeSent(vId: String, token: PhoneAuthProvider.ForceResendingToken) { onCodeSent(vId) }
    }).build())
}
fun signInAndVault(credential: PhoneAuthCredential, phone: String, profileUri: Uri?, context: Context, auth: FirebaseAuth, onState: (AuthState) -> Unit, onDone: (phone: String, pubKey: String) -> Unit) {
    auth.signInWithCredential(credential).addOnSuccessListener { result ->
        val myPhone = result.user?.phoneNumber ?: phone
        onState(AuthState.GeneratingKey); SignalKeyManager.getOrCreateIdentityKeyPair()
        val pubKey = SignalKeyManager.getPublicKeyBase64()
        if (pubKey == null) { onState(AuthState.AuthError("Key generation failed.")); return@addOnSuccessListener }
        onState(AuthState.PublishingKey)
        KeyRegistry.publishPublicKey(myPhone) { ok ->
            if (ok) {
                if (profileUri != null) { val base64String = encodeImageUriToBase64(context, profileUri); if (base64String != null) { FirebaseDatabase.getInstance().reference.child("users").child(myPhone.sanitise()).child("profilePicBase64").setValue(base64String) } }
                FirebaseMessaging.getInstance().token.addOnSuccessListener { token -> FirebaseDatabase.getInstance().reference.child("users").child(myPhone.sanitise()).child("fcmToken").setValue(token) }
                onState(AuthState.Done(myPhone, pubKey)); onDone(myPhone, pubKey)
            } else onState(AuthState.AuthError("Firebase publish failed."))
        }
    }.addOnFailureListener { e -> onState(AuthState.AuthError("OTP failed: ${e.message}")) }
}
fun startSmsRetriever(context: Context) { SmsRetriever.getClient(context).startSmsRetriever() }

// ─────────────────────────────────────────────────────────────────────────────
// BASE64 IMAGE COMPRESSOR (CRASH FIX: IN-SAMPLE-SIZE SCALING)
// ─────────────────────────────────────────────────────────────────────────────
fun encodeImageUriToBase64(context: Context, uri: Uri): String? {
    return try {
        // Step 1: Read the bounds of the image without loading it into memory to avoid OOM
        val options = android.graphics.BitmapFactory.Options().apply {
            inJustDecodeBounds = true
        }
        val boundStream = context.contentResolver.openInputStream(uri)
        android.graphics.BitmapFactory.decodeStream(boundStream, null, options)
        boundStream?.close()

        // Step 2: Calculate the downsampling scale (power of 2) to safely load the bitmap
        var scale = 1
        while (options.outWidth / scale / 2 >= 150 && options.outHeight / scale / 2 >= 150) {
            scale *= 2
        }

        // Step 3: Decode the actual image scaled down natively
        val scaledOptions = android.graphics.BitmapFactory.Options().apply {
            inSampleSize = scale
        }
        val imgStream = context.contentResolver.openInputStream(uri)
        val bitmap = android.graphics.BitmapFactory.decodeStream(imgStream, null, scaledOptions)
        imgStream?.close()

        if (bitmap == null) return null

        // Step 4: Final precise scale and compress
        val finalBitmap = android.graphics.Bitmap.createScaledBitmap(bitmap, 150, 150, true)
        val outputStream = java.io.ByteArrayOutputStream()
        finalBitmap.compress(android.graphics.Bitmap.CompressFormat.JPEG, 60, outputStream)
        Base64.encodeToString(outputStream.toByteArray(), Base64.NO_WRAP)
        
    } catch (e: Exception) {
        Log.e("Base64Hack", "Failed to compress image safely: ${e.message}")
        null
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILS
// ─────────────────────────────────────────────────────────────────────────────
fun formatTimestamp(ts: Long): String {
    if (ts == 0L) return ""
    val diff = System.currentTimeMillis() - ts
    return when { diff < 60000 -> "now"; diff < 3600000 -> "${diff / 60000}m"; diff < 86400000 -> SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(ts)); else -> SimpleDateFormat("dd/MM", Locale.getDefault()).format(Date(ts)) }
}
fun statusTick(status: String): String = when (status) { "sending" -> "🕒"; "sent" -> "✓"; "delivered" -> "✓✓"; "read" -> "✓✓"; else -> "" }

// ─────────────────────────────────────────────────────────────────────────────
// BACKGROUND SERVICES (FCM + ZOMBIE)
// ─────────────────────────────────────────────────────────────────────────────
class TextoMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        super.onNewToken(token)
        FirebaseAuth.getInstance().currentUser?.phoneNumber?.let { phone -> FirebaseDatabase.getInstance().reference.child("users").child(phone.sanitise()).child("fcmToken").setValue(token) }
    }
    override fun onMessageReceived(message: RemoteMessage) {
        super.onMessageReceived(message)
        showNotification(message.notification?.title ?: "Secure Message", message.notification?.body ?: "🔒 You have a new encrypted message")
    }
    private fun showNotification(title: String, body: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channelId = "texto_messages"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) { manager.createNotificationChannel(NotificationChannel(channelId, "Messages", NotificationManager.IMPORTANCE_HIGH)) }
        val intent = Intent(this, MainActivity::class.java).apply { flags = Intent.FLAG_ACTIVITY_CLEAR_TOP }
        val pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val builder = NotificationCompat.Builder(this, channelId).setSmallIcon(android.R.drawable.ic_dialog_info).setContentTitle(title).setContentText(body).setAutoCancel(true).setContentIntent(pendingIntent).setPriority(NotificationCompat.PRIORITY_HIGH)
        manager.notify(System.currentTimeMillis().toInt(), builder.build())
    }
}

class TextoZombieService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val channelId = "texto_zombie_channel"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(channelId, "Background Sync", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }

        val notification = NotificationCompat.Builder(this, channelId)
            .setContentTitle("TEXTO is securing your chats")
            .setContentText("Listening for encrypted messages...")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(1, notification)
        }

        FirebaseDatabase.getInstance().goOnline()
        return START_STICKY
    }
}