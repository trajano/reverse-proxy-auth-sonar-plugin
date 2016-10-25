class ReverseproxyauthController < ApplicationController
	skip_before_filter :check_authentication
	def redirect_back_or_home_url
		redirect_back_or_default(home_url)
	end
end
