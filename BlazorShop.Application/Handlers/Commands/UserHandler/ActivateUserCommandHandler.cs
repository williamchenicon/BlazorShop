﻿namespace BlazorShop.Application.Handlers.Commands.UserHandler
{
    public class ActivateUserCommandHandler : IRequestHandler<ActivateUserCommand, RequestResponse>
    {
        private readonly IUserService _userService;
        private readonly ILogger<ActivateUserCommandHandler> _logger;

        public ActivateUserCommandHandler(IUserService userService, ILogger<ActivateUserCommandHandler> logger)
        {
            _userService = userService;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<RequestResponse> Handle(ActivateUserCommand request, CancellationToken cancellationToken)
        {
            try
            {
                var result = await _userService.ActivateUserAsync(request);
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ErrorsManager.ActivateUserCommand);
                return RequestResponse.Failure($"{ErrorsManager.ActivateUserCommand}. {ex.Message}. {ex.InnerException?.Message}");
            }
        }
    }
}
