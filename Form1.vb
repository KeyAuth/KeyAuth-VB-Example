Imports KeyAuth_VB.KeyAuth
Public Class Form1
    Private Sub Form1_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        KeyAuthApp.init()
        Label2.Visible = False
    End Sub
    Private Shared name As String = "example"
    Private Shared ownerid As String = "oVXxM3uu77"
    Private Shared secret As String = "db40d586f4b189e04e5c18c3c94b7e72221be3f6551995adc05236948d1762bc"
    Private Shared version As String = "1.0"
    Public Shared KeyAuthApp As api = New api(name, ownerid, secret, version)
    Private Sub Button1_Click(sender As Object, e As EventArgs) Handles Button1.Click
        If KeyAuthApp.login(TextBox1.Text, TextBox2.Text) Then
            Button1.Visible = False
            Button2.Visible = False
            Button3.Visible = False
            Button4.Visible = False
            Label1.Visible = False
            Label2.Visible = False
            Label3.Visible = False
            Label4.Visible = False
            TextBox1.Visible = False
            TextBox2.Visible = False
            TextBox3.Visible = False
            Label2.Visible = True
        End If
    End Sub

    Private Sub Button2_Click(sender As Object, e As EventArgs) Handles Button2.Click
        If KeyAuthApp.register(TextBox1.Text, TextBox2.Text, TextBox3.Visible) Then
            Button1.Visible = False
            Button2.Visible = False
            Button3.Visible = False
            Button4.Visible = False
            Label1.Visible = False
            Label2.Visible = False
            Label3.Visible = False
            Label4.Visible = False
            TextBox1.Visible = False
            TextBox2.Visible = False
            TextBox3.Visible = False
            Label2.Visible = True
        End If
    End Sub

    Private Sub Button3_Click(sender As Object, e As EventArgs) Handles Button3.Click
        KeyAuthApp.upgrade(TextBox1.Text, TextBox3.Text)
    End Sub

    Private Sub Button4_Click(sender As Object, e As EventArgs) Handles Button4.Click
        If KeyAuthApp.license(TextBox3.Text) Then
            Button1.Visible = False
            Button2.Visible = False
            Button3.Visible = False
            Button4.Visible = False
            Label1.Visible = False
            Label2.Visible = False
            Label3.Visible = False
            Label4.Visible = False
            TextBox1.Visible = False
            TextBox2.Visible = False
            TextBox3.Visible = False
            Label2.Visible = True
        End If
    End Sub
End Class
