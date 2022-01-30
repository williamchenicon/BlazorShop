﻿namespace BlazorShop.Application.Handlers.Queries.RoleHandler
{
    public class GetRolesQueryHandler : IRequestHandler<GetRolesQuery, Result<RoleResponse>>
    {
        private readonly IRoleService _roleService;
        private readonly ILogger<GetRolesQueryHandler> _logger;

        public GetRolesQueryHandler(IRoleService roleService, ILogger<GetRolesQueryHandler> logger)
        {
            _roleService = roleService;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public Task<Result<RoleResponse>> Handle(GetRolesQuery request, CancellationToken cancellationToken)
        {
            try
            {
                var result = _roleService.GetRoles();

                return Task.FromResult(new Result<RoleResponse>
                {
                    Successful = true,
                    Items = result ?? new List<RoleResponse>()
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ErrorsManager.GetRolesQuery);
                return Task.FromResult(new Result<RoleResponse>
                {
                    Error = $"{ErrorsManager.GetRolesQuery}. {ex.Message}. {ex.InnerException?.Message}"
                });
            }
        }
    }
}
