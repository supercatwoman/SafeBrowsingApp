package com.example.safebrowsingapp

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.gson.annotations.SerializedName
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.POST

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val urlInput = findViewById<EditText>(R.id.urlInput)
        val checkButton = findViewById<Button>(R.id.checkButton)

        checkButton.setOnClickListener {
            val url = urlInput.text.toString().trim()
            if (url.isNotEmpty()) {
                checkUrlSafety(url)
            } else {
                Toast.makeText(this, "Введите URL", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun checkUrlSafety(url: String) {
        val retrofit = Retrofit.Builder()
            .baseUrl("https://safebrowsing.googleapis.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build()

        val api = retrofit.create(SafeBrowsingApi::class.java)

        val request = SafeBrowsingRequest(
            client = ClientInfo("safebrowsingapp", "1.0"),
            threatInfo = ThreatInfo(
                threatTypes = listOf("MALWARE", "SOCIAL_ENGINEERING"),
                platformTypes = listOf("ANY_PLATFORM"),
                threatEntryTypes = listOf("URL"),
                threatEntries = listOf(ThreatEntry(url))
            )
        )

        api.checkUrl(request).enqueue(object : Callback<SafeBrowsingResponse> {
            override fun onResponse(call: Call<SafeBrowsingResponse>, response: Response<SafeBrowsingResponse>) {
                val result = response.body()
                if (result?.matches != null) {
                    Toast.makeText(this@MainActivity, "Найден вредоносный сайт!", Toast.LENGTH_LONG).show()
                } else {
                    Toast.makeText(this@MainActivity, "Сайт безопасен", Toast.LENGTH_LONG).show()
                }
            }

            override fun onFailure(call: Call<SafeBrowsingResponse>, t: Throwable) {
                Toast.makeText(this@MainActivity, "Ошибка: ${t.message}", Toast.LENGTH_LONG).show()
            }
        })
    }
}

interface SafeBrowsingApi {
    @POST("v4/threatMatches:find?key=AIzaSyBbl8FcHmZpvchFNercjoAglpSJZsZ6K-Y")
    fun checkUrl(@Body request: SafeBrowsingRequest): Call<SafeBrowsingResponse>
}

data class SafeBrowsingRequest(
    val client: ClientInfo,
    val threatInfo: ThreatInfo
)

data class ClientInfo(
    val clientId: String,
    val clientVersion: String
)

data class ThreatInfo(
    val threatTypes: List<String>,
    val platformTypes: List<String>,
    val threatEntryTypes: List<String>,
    val threatEntries: List<ThreatEntry>
)

data class ThreatEntry(
    val url: String
)

data class SafeBrowsingResponse(
    @SerializedName("matches") val matches: List<Any>?
)