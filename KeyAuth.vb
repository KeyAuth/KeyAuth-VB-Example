Imports System
Imports System.Security.Cryptography
Imports System.Security.Cryptography.X509Certificates
Imports System.Collections.Specialized
Imports System.Text
Imports System.IO
Imports System.Net.Security
Imports System.Runtime.InteropServices
Imports System.Diagnostics
Imports System.Windows.Forms
Imports System.Security.Principal
Imports System.Net

Namespace KeyAuth
    Public Class api
        Public Shared Sub init(ByVal name As String, ByVal secret As String, ByVal ownerid As String)
            Dim init_iv = sha256(iv_key()) ' can be changed to whatever you want
            Dim values_to_upload = New NameValueCollection From {
                            {"type", byte_arr_to_str(Encoding.Default.GetBytes("init"))},
                            {"hash", checksum(Process.GetCurrentProcess().MainModule.FileName)},
                            {"name", byte_arr_to_str(Encoding.Default.GetBytes(name))},
                            {"ownerid", byte_arr_to_str(Encoding.Default.GetBytes(ownerid))},
                            {"init_iv", init_iv}
                        }
            Dim response = req(values_to_upload)
            response = decrypt(response, secret, init_iv)

            If Equals(response, "KeyAuth_Disabled") Then
                MessageBox.Show("This application is disabled")
                Environment.Exit(0)
            ElseIf Equals(response, "KeyAuth_WrongHash") Then
                MessageBox.Show("Application Hash is Incorrect. This program was modified since the hash was last set." & vbLf & "  Inform the application owner to 'reset app hash' in their settings")
                Environment.Exit(0)
                ' optional success message. Make sure to string encrypt for security
            ElseIf Equals(response, "KeyAuth_Initialized") Then
            Else
                MessageBox.Show("Application Failed To Connect. Try again or contact application owner")
                Environment.Exit(0)
            End If
        End Sub

        Public Shared Function login(ByVal key As String, ByVal name As String, ByVal secret As String, ByVal ownerid As String) As Boolean
            Dim hwid As String = WindowsIdentity.GetCurrent().User.Value
            Dim init_iv = sha256(iv_key()) ' can be changed to whatever you want
            Dim values_to_upload = New NameValueCollection From {
                            {"type", byte_arr_to_str(Encoding.Default.GetBytes("login"))},
                            {"key", encrypt(key, secret, init_iv)},
                            {"hwid", encrypt(hwid, secret, init_iv)},
                            {"name", byte_arr_to_str(Encoding.Default.GetBytes(name))},
                            {"ownerid", byte_arr_to_str(Encoding.Default.GetBytes(ownerid))},
                            {"init_iv", init_iv}
                        }
            Dim response = req(values_to_upload)
            response = decrypt(response, secret, init_iv)

            If Equals(response, "KeyAuth_Valid") Then
                Return True
            ElseIf Equals(response, "KeyAuth_Invalid") Then
                MessageBox.Show("Key not found.")
                Environment.Exit(0)
                Return False
            ElseIf Equals(response, "KeyAuth_InvalidHWID") Then
                MessageBox.Show("This computer doesn't match the computer the key is locked to. If you reset your computer, contact the application owner.")
                Environment.Exit(0)
                Return False
            ElseIf Equals(response, "KeyAuth_Expired") Then
                MessageBox.Show("This key is expired.")
                Environment.Exit(0)
                Return False
            Else
                MessageBox.Show("Failed to connect to login.")
                Environment.Exit(0)
                Return False
            End If
        End Function

        Public Shared Function checksum(ByVal filename As String) As String
            Dim result As String

            Using md As MD5 = MD5.Create()

                Using fileStream As FileStream = File.OpenRead(filename)
                    Dim value As Byte() = md.ComputeHash(fileStream)
                    result = BitConverter.ToString(value).Replace("-", "").ToLowerInvariant()
                End Using
            End Using

            Return result
        End Function

        Private Shared Function req(ByVal post_data As NameValueCollection) As String
            Using client As WebClient = New WebClient()
                client.Headers("User-Agent") = "KeyAuth"

                ' ServicePointManager.ServerCertificateValidationCallback = others.pin_public_key;

                Dim raw_response = client.UploadValues("https://keyauth.com/api/", post_data)

                ' ServicePointManager.ServerCertificateValidationCallback += (send, certificate, chain, sslPolicyErrors) => { return true; };

                Return Encoding.Default.GetString(raw_response)
            End Using
        End Function
    End Class

    Public Module others
        Public Function unix_to_date(ByVal unixTimeStamp As Double) As Date
            Return New DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixTimeStamp).ToLocalTime()
        End Function

        Public Function pin_public_key(ByVal sender As Object, ByVal certificate As X509Certificate, ByVal chain As X509Chain, ByVal sslPolicyErrors As SslPolicyErrors) As Boolean
            Return Equals(certificate.GetPublicKeyString(), "3082010A0282010100C7429D4B4591E50FE4B3ABDA72DB3F3EA578E12B9CD4E228E4EDFAC3F9681F354C913386A13E88181D1B14D91723FB50770C5DC94FCA59D4DEE4F6632041EFE76C3B6BCFF6B8F5B38AF92547D04BD08AF71087B094F5DFE8760C8CD09A3771836807588B02282BEC7C4CD73EE7C650C0A7C7F36F2FA56DA17E892B2760C4C75950EA5C90CD4EA301EC0CBC36B8372FE8515A7131CC6DF13A97D95B94C6A92AC4E5BFF217FCB20B3C01DB085229E919555D426D919E9A9F0D4C599FE7473FA7DBDE9B33279E2FC29F6CE09FA1269409E4A82175C8E0B65723DB6F856A53E3FD11363ADD63D1346790A3E4D1E454D1714ECED9815A0F85C5019C0D4DC3D58234C10203010001")
        End Function
    End Module

    Public Module encryption
        Public Function byte_arr_to_str(ByVal ba As Byte()) As String
            Dim hex As StringBuilder = New StringBuilder(ba.Length * 2)

            For Each b As Byte In ba
                hex.AppendFormat("{0:x2}", b)
            Next

            Return hex.ToString()
        End Function

        Public Function str_to_byte_arr(ByVal hex As String) As Byte()
            Dim NumberChars As Integer = hex.Length
            Dim bytes As Byte() = New Byte(NumberChars / 2 - 1) {}

            For i As Integer = 0 To NumberChars - 1 Step 2
                bytes(i / 2) = Convert.ToByte(hex.Substring(i, 2), 16)
            Next

            Return bytes
        End Function

        Public Function encrypt_string(ByVal plain_text As String, ByVal key As Byte(), ByVal iv As Byte()) As String
            Dim encryptor As Aes = Aes.Create()
            encryptor.Mode = CipherMode.CBC
            encryptor.Key = key
            encryptor.IV = iv

            Using mem_stream As MemoryStream = New MemoryStream()

                Using aes_encryptor As ICryptoTransform = encryptor.CreateEncryptor()

                    Using crypt_stream As CryptoStream = New CryptoStream(mem_stream, aes_encryptor, CryptoStreamMode.Write)
                        Dim p_bytes As Byte() = Encoding.Default.GetBytes(plain_text)
                        crypt_stream.Write(p_bytes, 0, p_bytes.Length)
                        crypt_stream.FlushFinalBlock()
                        Dim c_bytes As Byte() = mem_stream.ToArray()
                        Return byte_arr_to_str(c_bytes)
                    End Using
                End Using
            End Using
        End Function

        Public Function decrypt_string(ByVal cipher_text As String, ByVal key As Byte(), ByVal iv As Byte()) As String
            Dim encryptor As Aes = Aes.Create()
            encryptor.Mode = CipherMode.CBC
            encryptor.Key = key
            encryptor.IV = iv

            Using mem_stream As MemoryStream = New MemoryStream()

                Using aes_decryptor As ICryptoTransform = encryptor.CreateDecryptor()

                    Using crypt_stream As CryptoStream = New CryptoStream(mem_stream, aes_decryptor, CryptoStreamMode.Write)
                        Dim c_bytes As Byte() = str_to_byte_arr(cipher_text)
                        crypt_stream.Write(c_bytes, 0, c_bytes.Length)
                        crypt_stream.FlushFinalBlock()
                        Dim p_bytes As Byte() = mem_stream.ToArray()
                        Return Encoding.Default.GetString(p_bytes, 0, p_bytes.Length)
                    End Using
                End Using
            End Using
        End Function

        Public Function iv_key() As String
            Return Guid.NewGuid().ToString().Substring(0, Guid.NewGuid().ToString().IndexOf("-", StringComparison.Ordinal))
        End Function

        Public Function sha256(ByVal r As String) As String
            Return byte_arr_to_str(New SHA256Managed().ComputeHash(Encoding.Default.GetBytes(r)))
        End Function

        Public Function encrypt(ByVal message As String, ByVal enc_key As String, ByVal iv As String) As String
            Dim _key As Byte() = Encoding.Default.GetBytes(sha256(enc_key).Substring(0, 32))
            Dim _iv As Byte() = Encoding.Default.GetBytes(sha256(iv).Substring(0, 16))
            Return encrypt_string(message, _key, _iv)
        End Function

        Public Function decrypt(ByVal message As String, ByVal enc_key As String, ByVal iv As String) As String
            Dim _key As Byte() = Encoding.Default.GetBytes(sha256(enc_key).Substring(0, 32))
            Dim _iv As Byte() = Encoding.Default.GetBytes(sha256(iv).Substring(0, 16))
            Return decrypt_string(message, _key, _iv)
        End Function

        Public Function unix_to_date(ByVal unixTimeStamp As Double) As Date
            Return New DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixTimeStamp).ToLocalTime()
        End Function

        Public Function pin_public_key(ByVal sender As Object, ByVal certificate As X509Certificate, ByVal chain As X509Chain, ByVal sslPolicyErrors As SslPolicyErrors) As Boolean
            Return Equals(certificate.GetPublicKeyString(), "3082010A0282010100C7429D4B4591E50FE4B3ABDA72DB3F3EA578E12B9CD4E228E4EDFAC3F9681F354C913386A13E88181D1B14D91723FB50770C5DC94FCA59D4DEE4F6632041EFE76C3B6BCFF6B8F5B38AF92547D04BD08AF71087B094F5DFE8760C8CD09A3771836807588B02282BEC7C4CD73EE7C650C0A7C7F36F2FA56DA17E892B2760C4C75950EA5C90CD4EA301EC0CBC36B8372FE8515A7131CC6DF13A97D95B94C6A92AC4E5BFF217FCB20B3C01DB085229E919555D426D919E9A9F0D4C599FE7473FA7DBDE9B33279E2FC29F6CE09FA1269409E4A82175C8E0B65723DB6F856A53E3FD11363ADD63D1346790A3E4D1E454D1714ECED9815A0F85C5019C0D4DC3D58234C10203010001")
        End Function
    End Module
End Namespace
