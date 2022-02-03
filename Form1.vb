Imports KeyAuth_VB.KeyAuth
Public Class Form1
    Private Sub Form1_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        KeyAuthApp.init()
        Label2.Visible = False
    End Sub
    Private Shared name As String = "" ' Application name, found in dashboard
    Private Shared ownerid As String = "" ' Ownerid, found in account settings of dashboard
    Private Shared secret As String = "" ' Application name, found in dashboard. It's the blurred text beneath application name
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
        If KeyAuthApp.register(TextBox1.Text, TextBox2.Text, TextBox3.Text) Then
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
