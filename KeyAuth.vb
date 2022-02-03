Imports System
Imports System.Security.Cryptography
Imports System.Security.Cryptography.X509Certificates
Imports System.Collections.Specialized
Imports System.Text
Imports System.Net
Imports System.IO
Imports System.Net.Security
Imports System.Runtime.Serialization
Imports System.Runtime.Serialization.Json
Imports System.Security.Principal
Imports Dynamitey

Namespace KeyAuth
    Public Class api
        Public name, ownerid, secret, version As String

        Public Sub New(ByVal name As String, ByVal ownerid As String, ByVal secret As String, ByVal version As String)
            If String.IsNullOrWhiteSpace(name) OrElse String.IsNullOrWhiteSpace(ownerid) OrElse String.IsNullOrWhiteSpace(secret) OrElse String.IsNullOrWhiteSpace(version) Then
                MessageBox.Show("Application not setup correctly. Please watch video link found in Login.cs")
                Environment.Exit(0)
            End If

            Me.name = name
            Me.ownerid = ownerid
            Me.secret = secret
            Me.version = version
        End Sub

        Public sessionid, enckey As String
#Region "structures"
        <DataContract>
        Private Class response_structure
            <DataMember>
            Public Property success As Boolean
            <DataMember>
            Public Property response As String
            <DataMember>
            Public Property message As String
            <DataMember>
            Public Property download As String
            <DataMember>
            Public Property sessionid As String
            <DataMember(IsRequired:=False, EmitDefaultValue:=False)>
            Public Property info As user_data_structure
        End Class

        <DataContract>
        Private Class user_data_structure
            <DataMember>
            Public Property key As String
            <DataMember>
            Public Property expiry As String 'timestamp
            <DataMember>
            Public Property level As Integer
        End Class

#End Region

        Public Sub init()
            enckey = sha256(iv_key())
            Dim init_iv = sha256(iv_key())
            Dim values_to_upload = New NameValueCollection From {
                            {"type", byte_arr_to_str(Encoding.Default.GetBytes("init"))},
                            {"ver", encrypt(version, secret, init_iv)},
                            {"hash", checksum(Process.GetCurrentProcess().MainModule.FileName)},
                            {"enckey", encrypt(enckey, secret, init_iv)},
                            {"name", byte_arr_to_str(Encoding.Default.GetBytes(name))},
                            {"ownerid", byte_arr_to_str(Encoding.Default.GetBytes(ownerid))},
                            {"init_iv", init_iv}
                        }
            Dim response = req(values_to_upload)
            response = decrypt(response, secret, init_iv)
            Dim json = response_decoder.string_to_generic(Of response_structure)(response)

            If json.message = "invalidver" Then
                Process.Start(json.download)
                Environment.Exit(0)
            ElseIf Not json.success Then
                MessageBox.Show(json.message)
                Environment.Exit(0)
            Else
                sessionid = json.sessionid
            End If
        End Sub

        Public Function login(ByVal username As String, ByVal pass As String) As Boolean
            Dim hwid = WindowsIdentity.GetCurrent().User.Value
            Dim init_iv = sha256(iv_key()) ' can be changed to whatever you want
            Dim values_to_upload = New NameValueCollection From {
                            {"type", byte_arr_to_str(Encoding.Default.GetBytes("login"))},
                            {"username", encrypt(username, enckey, init_iv)},
                            {"pass", encrypt(pass, enckey, init_iv)},
                            {"hwid", encrypt(hwid, enckey, init_iv)},
                            {"sessionid", byte_arr_to_str(Encoding.Default.GetBytes(sessionid))},
                            {"name", byte_arr_to_str(Encoding.Default.GetBytes(name))},
                            {"ownerid", byte_arr_to_str(Encoding.Default.GetBytes(ownerid))},
                            {"init_iv", init_iv}
                        }
            Dim response = req(values_to_upload)
            response = decrypt(response, enckey, init_iv)
            Dim json = response_decoder.string_to_generic(Of response_structure)(response)

            If Not json.success Then
                MessageBox.Show(json.message)
                Return False
            Else
                load_user_data(json.info)
                Return True
            End If
        End Function
        Public Function register(ByVal username As String, ByVal pass As String, ByVal key As String) As Boolean
            Dim hwid = WindowsIdentity.GetCurrent().User.Value
            Dim init_iv = sha256(iv_key()) ' can be changed to whatever you want
            Dim values_to_upload = New NameValueCollection From {
                            {"type", byte_arr_to_str(Encoding.Default.GetBytes("register"))},
                            {"username", encrypt(username, enckey, init_iv)},
                            {"pass", encrypt(pass, enckey, init_iv)},
                            {"key", encrypt(key, enckey, init_iv)},
                            {"hwid", encrypt(hwid, enckey, init_iv)},
                            {"sessionid", byte_arr_to_str(Encoding.Default.GetBytes(sessionid))},
                            {"name", byte_arr_to_str(Encoding.Default.GetBytes(name))},
                            {"ownerid", byte_arr_to_str(Encoding.Default.GetBytes(ownerid))},
                            {"init_iv", init_iv}
                        }
            Dim response = req(values_to_upload)
            response = decrypt(response, enckey, init_iv)
            Dim json = response_decoder.string_to_generic(Of response_structure)(response)

            If Not json.success Then
                MessageBox.Show(json.message)
                Return False
            Else
                load_user_data(json.info)
                Return True
            End If
        End Function
        Public Sub upgrade(ByVal username As String, ByVal key As String)
            Dim hwid = WindowsIdentity.GetCurrent().User.Value
            Dim init_iv = sha256(iv_key()) ' can be changed to whatever you want
            Dim values_to_upload = New NameValueCollection From {
                            {"type", byte_arr_to_str(Encoding.Default.GetBytes("upgrade"))},
                            {"username", encrypt(username, enckey, init_iv)},
                            {"key", encrypt(key, enckey, init_iv)},
                            {"sessionid", byte_arr_to_str(Encoding.Default.GetBytes(sessionid))},
                            {"name", byte_arr_to_str(Encoding.Default.GetBytes(name))},
                            {"ownerid", byte_arr_to_str(Encoding.Default.GetBytes(ownerid))},
                            {"init_iv", init_iv}
                        }
            Dim response = req(values_to_upload)
            response = decrypt(response, enckey, init_iv)
            Dim json = response_decoder.string_to_generic(Of response_structure)(response)

            If Not json.success Then
                MessageBox.Show(json.message)
            Else
                MessageBox.Show(json.message)
            End If
        End Sub
        Public Function license(ByVal key As String) As Boolean
            Dim hwid = WindowsIdentity.GetCurrent().User.Value
            Dim init_iv = sha256(iv_key()) ' can be changed to whatever you want
            Dim values_to_upload = New NameValueCollection From {
                            {"type", byte_arr_to_str(Encoding.Default.GetBytes("license"))},
                            {"key", encrypt(key, enckey, init_iv)},
                            {"hwid", encrypt(hwid, enckey, init_iv)},
                            {"sessionid", byte_arr_to_str(Encoding.Default.GetBytes(sessionid))},
                            {"name", byte_arr_to_str(Encoding.Default.GetBytes(name))},
                            {"ownerid", byte_arr_to_str(Encoding.Default.GetBytes(ownerid))},
                            {"init_iv", init_iv}
                        }
            Dim response = req(values_to_upload)
            response = decrypt(response, enckey, init_iv)
            Dim json = response_decoder.string_to_generic(Of response_structure)(response)

            If Not json.success Then
                MessageBox.Show(json.message)
                Return False
            Else
                load_user_data(json.info)
                Return True
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
            Try

                Using client As WebClient = New WebClient()
                    client.Headers("User-Agent") = "KeyAuth"
                    ' ServicePointManager.ServerCertificateValidationCallback = AddressOf others.pin_public_key
                    Dim raw_response = client.UploadValues("https://keyauth.win/api/1.0/", post_data)
                    ' ServicePointManager.ServerCertificateValidationCallback = Function(send, certificate, chain, sslPolicyErrors) True
                    Return Encoding.Default.GetString(raw_response)
                End Using

            Catch
                MessageBox.Show("Connection error")
                Environment.Exit(0)
                Return ""
            End Try
        End Function



#Region "user_data"
        Public user_data As user_data_class = New user_data_class()

        Public Class user_data_class
            Public Property key As String
            Public Property expiry As Date
            Public Property level As Integer
        End Class

        Private Sub load_user_data(ByVal data As user_data_structure)
            user_data.key = data.key
            user_data.expiry = others.unix_to_date(Convert.ToDouble(data.expiry))
            user_data.level = data.level
        End Sub

#End Region

        Private response_decoder As json_wrapper = New json_wrapper(New response_structure())
    End Class

    Public Module others
        Public Function unix_to_date(ByVal unixTimeStamp As Double) As Date
            Return New DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixTimeStamp).ToLocalTime()
        End Function

        Public Function pin_public_key(ByVal sender As Object, ByVal certificate As X509Certificate, ByVal chain As X509Chain, ByVal sslPolicyErrors As SslPolicyErrors) As Boolean
            Return Equals(certificate.GetPublicKeyString(), "3082010A028201010082BD4F6711C71AB8716DC67EB8C48B0535E910D49D6F5F125D37A68AE0907FA108FF4F975B9CB58036539C3BBD177912DCE101D871D60DD3A5B84176E89B45F991FE7952FA6DC39C8F0C38798F9312AC523093D1F93EFE16DC7212184AC516E983DCD998DAA543211206171C28795A85A079809F364CC991518B7A31F71B166B6763989D9B6A317B6E3C3F3D01BD516EF76B5FEA5978EFC422C9B870867800C16F204137C8A0A811D058CC657E37EA6DD84E68A9F73E2D52D08EFE4E743A85C27ACFAB2EBBD68797529B17B74C9033D019E1383E3CD34D1088342A67148295704A7192502A5299503510B6F07978D1D42A884DE2F830A6FC393136E9F0C245D50203010001")
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
            Return Equals(certificate.GetPublicKeyString(), "3082010A028201010082BD4F6711C71AB8716DC67EB8C48B0535E910D49D6F5F125D37A68AE0907FA108FF4F975B9CB58036539C3BBD177912DCE101D871D60DD3A5B84176E89B45F991FE7952FA6DC39C8F0C38798F9312AC523093D1F93EFE16DC7212184AC516E983DCD998DAA543211206171C28795A85A079809F364CC991518B7A31F71B166B6763989D9B6A317B6E3C3F3D01BD516EF76B5FEA5978EFC422C9B870867800C16F204137C8A0A811D058CC657E37EA6DD84E68A9F73E2D52D08EFE4E743A85C27ACFAB2EBBD68797529B17B74C9033D019E1383E3CD34D1088342A67148295704A7192502A5299503510B6F07978D1D42A884DE2F830A6FC393136E9F0C245D50203010001")
        End Function
    End Module

    Public Class json_wrapper
        Public Shared Function is_serializable(ByVal to_check As Type) As Boolean
            Return to_check.IsSerializable OrElse to_check.IsDefined(GetType(DataContractAttribute), True)
        End Function

        Public Sub New(ByVal obj_to_work_with As Object)
            current_object = obj_to_work_with
            Dim object_type = current_object.GetType()
            serializer = New DataContractJsonSerializer(object_type)
            If Not is_serializable(object_type) Then Throw New Exception($"the object {current_object} isn't a serializable")
        End Sub

        Public Function to_json_string() As String
            Using mem_stream = New MemoryStream()
                serializer.WriteObject(mem_stream, current_object)
                mem_stream.Position = 0

                Using reader = New StreamReader(mem_stream)
                    Return reader.ReadToEnd()
                End Using
            End Using
        End Function

        Public Function string_to_object(ByVal json As String) As Object
            Dim buffer = Encoding.Default.GetBytes(json)


            'SerializationException = session expired

            Using mem_stream = New MemoryStream(buffer)
                Return serializer.ReadObject(mem_stream)
            End Using
        End Function


#Region "extras"

        Public Function string_to_dynamic(ByVal json As String) As Dynamic
            Return CType(string_to_object(json), Dynamic)
        End Function

        Public Function string_to_generic(Of T)(ByVal json As String) As T
            Return string_to_object(json)
        End Function

        Public Function to_json_dynamic() As Dynamic
            Return string_to_object(to_json_string())
        End Function


#End Region

        Private serializer As DataContractJsonSerializer
        Private current_object As Object
    End Class
End Namespace