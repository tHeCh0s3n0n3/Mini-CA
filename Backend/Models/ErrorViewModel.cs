using System;

namespace Backend.Models
{
    public class ErrorViewModel
    {
        public string RequestId { get; set; }

        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

        public ErrorViewModel()
        {
            RequestId = string.Empty;
        }

        public ErrorViewModel(string requestId)
        {
            RequestId = requestId;
        }

    }
}
