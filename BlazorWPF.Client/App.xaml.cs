﻿using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace BlazorWPF.Client
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            // see https://learn.microsoft.com/en-us/aspnet/core/blazor/hybrid/?view=aspnetcore-7.0
            AppDomain.CurrentDomain.UnhandledException += (sender, error) =>
            {
                MessageBox.Show("An error has occurred.", "Error");
                // Log the error information (error.ExceptionObject)
            };
            base.OnStartup(e);
        }
    }
}