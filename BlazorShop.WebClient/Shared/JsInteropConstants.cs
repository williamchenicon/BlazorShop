﻿namespace BlazorShop.WebClient.Shared
{
    public static class JsInteropConstants
    {
        private const string FuncPrefix = "blazorDemo";

        public const string GetSessionStorage = $"{FuncPrefix}.getSessionStorage";

        public const string SetSessionStorage = $"{FuncPrefix}.setSessionStorage";

        public const string HideModal = $"{FuncPrefix}.hideModal";
    }
}
