package com.learetechno.aescryptandroid

import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*
import java.security.GeneralSecurityException

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {
    @Test
    fun useAppContext() {
        val password = "password2"
        val message = "hello world"

        if (BuildConfig.DEBUG){
            Aescrypt.DEBUG_LOG_ENABLED = true
        }

        var encryptedMsg: String? = null
        try {
            encryptedMsg = Aescrypt.encrypt(password, message)
            Log.d("encrypt", encryptedMsg!!)
            System.out.println("Encrypt $encryptedMsg")
        } catch (e: GeneralSecurityException) {
            fail("error occurred during encrypt")
            e.printStackTrace()
        }
        var messageAfterDecrypt: String? = null
        try {
            messageAfterDecrypt = Aescrypt.decrypt(password, encryptedMsg!!)
            Log.d("decrypt", messageAfterDecrypt!!)
        } catch (e: GeneralSecurityException) {
            fail("error occurred during Decrypt")
            e.printStackTrace()
        }
        if (messageAfterDecrypt != message) {
            fail("messages don't match after encrypt and decrypt")
        }
    }
}
