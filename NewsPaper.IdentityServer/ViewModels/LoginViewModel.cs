using System.ComponentModel.DataAnnotations;

namespace NewsPaper.IdentityServer.ViewModels
{
    public class LoginViewModel
    {
        [Required]
        public string UserName { get; set; } = "IdentityAuthor";

        [Required] 
        public string Password { get; set; } = "123qwe";

        [Required]
        public string ReturnUrl { get; set; }
    }
}