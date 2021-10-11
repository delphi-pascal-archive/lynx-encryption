object MainForm: TMainForm
  Left = 218
  Top = 132
  BorderIcons = [biSystemMenu, biMinimize]
  BorderStyle = bsSingle
  Caption = 'Lynx encryption - 128 bit'
  ClientHeight = 193
  ClientWidth = 400
  Color = clBtnFace
  Font.Charset = RUSSIAN_CHARSET
  Font.Color = clWindowText
  Font.Height = -15
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnClose = FormClose
  OnCreate = FormCreate
  PixelsPerInch = 120
  TextHeight = 16
  object PasswordLbl: TLabel
    Left = 10
    Top = 10
    Width = 112
    Height = 16
    Caption = 'Clef de chiffrement:'
  end
  object IVLbl: TLabel
    Left = 10
    Top = 41
    Width = 132
    Height = 16
    Caption = 'Vecteur d'#39'initialisation:'
  end
  object SepBevel1: TBevel
    Left = 10
    Top = 70
    Width = 382
    Height = 3
  end
  object FileLbl: TLabel
    Left = 10
    Top = 85
    Width = 25
    Height = 16
    Caption = 'File:'
  end
  object SepBevel2: TBevel
    Left = 10
    Top = 116
    Width = 382
    Height = 3
  end
  object PasswordEdit: TEdit
    Left = 162
    Top = 6
    Width = 230
    Height = 24
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = []
    ParentFont = False
    TabOrder = 0
  end
  object IVEdit: TEdit
    Left = 179
    Top = 37
    Width = 213
    Height = 24
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = []
    MaxLength = 16
    ParentFont = False
    TabOrder = 1
    Text = '7A9C840AF8472291'
  end
  object FileEdit: TEdit
    Left = 71
    Top = 81
    Width = 213
    Height = 24
    TabOrder = 2
  end
  object BrowseBtn: TButton
    Left = 291
    Top = 80
    Width = 101
    Height = 31
    Caption = 'Select file...'
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = []
    ParentFont = False
    TabOrder = 3
    OnClick = BrowseBtnClick
  end
  object EncryptBtn: TButton
    Left = 10
    Top = 125
    Width = 125
    Height = 32
    Caption = 'Crypt'
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = []
    ParentFont = False
    TabOrder = 4
    OnClick = EncryptBtnClick
  end
  object DecryptBtn: TButton
    Tag = 1
    Left = 144
    Top = 125
    Width = 139
    Height = 32
    Caption = 'Encrypt'
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = []
    ParentFont = False
    TabOrder = 5
    OnClick = EncryptBtnClick
  end
  object QuitBtn: TButton
    Left = 291
    Top = 125
    Width = 101
    Height = 32
    Caption = 'Exit'
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = []
    ParentFont = False
    TabOrder = 6
    OnClick = QuitBtnClick
  end
  object Bar: TProgressBar
    Left = 10
    Top = 165
    Width = 382
    Height = 21
    Max = 0
    TabOrder = 7
  end
  object OpenDlg: TOpenDialog
    Filter = 'Tous les fichiers|*.*'
    Title = 'Choisir un fichier ...'
    Left = 144
    Top = 16
  end
end
