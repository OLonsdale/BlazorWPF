﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using BlazorWPF.Client.Data;
using Microsoft.Extensions.DependencyInjection;
using MudBlazor.Services;

namespace BlazorWPF.Client
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            var serviceCollection = new ServiceCollection();
            serviceCollection.AddWpfBlazorWebView();
            serviceCollection.AddMudServices();
            serviceCollection.AddBlazorWebViewDeveloperTools(); //open with ctrl+shift+i
            serviceCollection.AddSingleton<DataService>();
            serviceCollection.AddSingleton<CardReaderService>();
            Resources.Add("services", serviceCollection.BuildServiceProvider());
            InitializeComponent();
            
        }
    }
}