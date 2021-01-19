Imports KeyAuth_VB.KeyAuth
Public Class Form1
    Private Sub Form1_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        Label2.Visible = False
    End Sub
    Private Shared name As String = ""
    Private Shared ownerid As String = ""
    Private Shared secret As String = ""
    Private Shared version As String = "1.0"
    Public Shared KeyAuthApp As api = New api(name, ownerid, secret, version)
    Private Sub Button1_Click(sender As Object, e As EventArgs) Handles Button1.Click
        If KeyAuthApp.login(TextBox1.Text) Then
            Button1.Visible = False
            Label1.Visible = False
            TextBox1.Visible = False
            Label2.Visible = True
        End If
    End Sub
End Class
