using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations;

namespace Backend.Models
{
    public class UploadFileModel
    {
        [Required]
        [Display(Name = "CSR File")]
        public IFormFile? FormFile { get; set; }
    }
}
