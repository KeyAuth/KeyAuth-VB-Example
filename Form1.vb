Imports KeyAuth_VB.KeyAuth
Public Class Form1
    Private Sub Form1_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        Label2.Visible = False
    End Sub
    Public name As String = "" ' app name here
    Public ownerid As String = "" ' owner id here
    Public secret As String = "" ' app secret here
    Private Sub Button1_Click(sender As Object, e As EventArgs) Handles Button1.Click
        If api.login(TextBox1.Text, Name, secret, ownerid) Then
            Button1.Visible = False
            Label1.Visible = False
            TextBox1.Visible = False
            Label2.Visible = True
        End If
    End Sub
End Class
